from __future__ import annotations

from pathlib import Path

import pytest

import reprobit.classic_cache as classic_cache_module
from reprobit.cache import IncrementalCache
from reprobit.classic_cache import (
    CompilerDependencyHint,
    DonorDependencyResolutionContext,
    DonorDependencyTrace,
    DonorResolvedDependencies,
    DonorTransformDependencyHint,
    compiler_base_key,
    compiler_final_key,
    compiler_hint_metadata,
    donor_transform_authority_paths,
    donor_transform_base_key,
    donor_transform_final_key,
    donor_transform_hint_metadata,
    probe_compiler_cache,
    probe_donor_transform_cache,
)
from reprobit.classic_includes import (
    IncludeOrigin,
    MsvcSbrSource,
    ResolvedInclude,
    SealedIncludeAuthority,
    SealedIncludeFile,
)
from reprobit.incremental import PRODUCER_CACHE_IMPLEMENTATION
from reprobit.model import Digest


def _material() -> dict[str, object]:
    return {
        "graph": "graph",
        "node": "compiler.unit",
        "role": "compiler",
        "toolchain": [{"path": "bin/CL.EXE", "digest": "1" * 64}],
        "runtime": [],
        "argv": ["/c", "R:/source/src/unit.cpp"],
        "cwd": "R:/build",
        "environment": {"INCLUDE": ["R:/source/include"]},
        "path_profile": "stable",
        "direct_inputs": [{"path": "source/src/unit.cpp", "digest": "2" * 64}],
        "producer_dependencies": [],
        "recursive_reads": [],
        "overlay_inputs": [],
        "generated_inputs": [],
        "donor_inputs": [],
        "composition_inputs": [],
        "transform_inputs": [],
    }


def _authority(header: bytes, *, shadow: bool = False) -> SealedIncludeAuthority:
    files = [
        SealedIncludeFile(
            r"R:\source\include\common.h",
            Digest.from_bytes(header),
            len(header),
            IncludeOrigin.PROJECT_SOURCE,
        ),
        SealedIncludeFile(
            r"R:\source\src\unit.cpp",
            Digest.from_bytes(b"source"),
            6,
            IncludeOrigin.PROJECT_SOURCE,
        ),
    ]
    if shadow:
        files.append(
            SealedIncludeFile(
                r"R:\source\src\common.h",
                Digest.from_bytes(b"shadow"),
                6,
                IncludeOrigin.PROJECT_SOURCE,
            )
        )
    return SealedIncludeAuthority(
        (r"R:\source", r"R:\toolchain"),
        tuple(sorted(files, key=lambda item: item.logical_path.casefold())),
    )


def _hint(base: str) -> CompilerDependencyHint:
    return CompilerDependencyHint(
        base,
        r"R:\build",
        (
            MsvcSbrSource(r"R:\source\src\unit.cpp", None),
            MsvcSbrSource("common.h", 0),
        ),
    )


def _donor_context(
    header: bytes,
    *,
    unrelated: bytes = b"unrelated",
) -> DonorDependencyResolutionContext:
    source_header = r"R:\source\include\common.h"
    mirror_header = r"R:\donors\fixture\inc\source\include\common.h"
    source_unrelated = r"R:\source\include\unrelated.h"
    mirror_unrelated = r"R:\donors\fixture\inc\source\include\unrelated.h"
    files = (
        SealedIncludeFile(
            source_header,
            Digest.from_bytes(header),
            len(header),
            IncludeOrigin.PROJECT_SOURCE,
        ),
        SealedIncludeFile(
            source_unrelated,
            Digest.from_bytes(unrelated),
            len(unrelated),
            IncludeOrigin.PROJECT_SOURCE,
        ),
        SealedIncludeFile(
            mirror_header,
            Digest.from_bytes(header),
            len(header),
            IncludeOrigin.DONOR_ARENA,
        ),
        SealedIncludeFile(
            mirror_unrelated,
            Digest.from_bytes(unrelated),
            len(unrelated),
            IncludeOrigin.DONOR_ARENA,
        ),
        SealedIncludeFile(
            r"R:\donors\fixture\s.cpp",
            Digest.from_bytes(b"donor source"),
            len(b"donor source"),
            IncludeOrigin.DONOR_ARENA,
        ),
    )
    return DonorDependencyResolutionContext(
        "donor.fixture",
        r"R:\donors\fixture",
        r"R:\donors\fixture\s.cpp",
        (r"R:\donors\fixture\inc\source\include",),
        (),
        (),
        SealedIncludeAuthority(
            (r"R:\donors\fixture", r"R:\source", r"R:\toolchain"),
            tuple(sorted(files, key=lambda item: item.logical_path.casefold())),
        ),
        (
            (mirror_header, source_header),
            (mirror_unrelated, source_unrelated),
        ),
    )


def test_projected_donor_hint_ignores_unread_mirror_files_and_tracks_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    output = tmp_path / "unit.obj"
    output.write_bytes(b"transformed object")
    cache = IncrementalCache(state, implementation=PRODUCER_CACHE_IMPLEMENTATION)
    material = _material()
    material["role"] = "compiler-transform"
    material["donor_inputs"] = [{"donor": "fixture"}]
    base = donor_transform_base_key(material)  # type: ignore[arg-type]
    trace = DonorDependencyTrace(
        "donor.fixture",
        r"R:\donors\fixture",
        (
            MsvcSbrSource("s.cpp", None),
            MsvcSbrSource("common.h", 0),
        ),
    )
    dependencies = (
        DonorResolvedDependencies(
            trace.donor_id,
            (
                ResolvedInclude(
                    "s.cpp",
                    r"R:\donors\fixture\s.cpp",
                    Digest.from_bytes(b"donor source"),
                    len(b"donor source"),
                    IncludeOrigin.DONOR_ARENA,
                    None,
                ),
                ResolvedInclude(
                    "common.h",
                    r"R:\donors\fixture\inc\source\include\common.h",
                    Digest.from_bytes(b"one"),
                    3,
                    IncludeOrigin.DONOR_ARENA,
                    0,
                ),
            ),
        ),
    )
    key = donor_transform_final_key(material, dependencies)  # type: ignore[arg-type]
    hint = DonorTransformDependencyHint(base, (trace,))
    with cache.lease() as lease:
        record = lease.store(
            "producer",
            key,
            {"build/unit.obj": output},
            metadata=donor_transform_hint_metadata(hint),
        )
        lease.index_record("producer", "donor-transform-base", base, record)
        stale_material = dict(material)
        stale_material["recursive_reads"] = [{"stale": True}]
        stale_key = classic_cache_module.producer_cache_key(  # type: ignore[arg-type]
            stale_material
        )
        stale_hint = DonorTransformDependencyHint(
            base,
            (
                DonorDependencyTrace(
                    "donor.fixture",
                    r"R:\donors\fixture",
                    (
                        MsvcSbrSource("s.cpp", None),
                        MsvcSbrSource("missing.h", 0),
                    ),
                ),
            ),
        )
        stale = lease.store(
            "producer",
            stale_key,
            {"build/unit.obj": output},
            metadata=donor_transform_hint_metadata(stale_hint),
        )
        lease.index_record("producer", "donor-transform-base", base, stale)
        original_index = classic_cache_module.index_sealed_include_authority
        index_calls = 0

        def counted_index(authority: SealedIncludeAuthority) -> object:
            nonlocal index_calls
            index_calls += 1
            return original_index(authority)

        monkeypatch.setattr(
            classic_cache_module,
            "index_sealed_include_authority",
            counted_index,
        )
        unrelated_edit = probe_donor_transform_cache(
            lease,
            base_key=base,
            base_material=material,  # type: ignore[arg-type]
            contexts=(_donor_context(b"one", unrelated=b"changed"),),
        )
        assert unrelated_edit.record == record
        assert index_calls == 1
        assert donor_transform_authority_paths(
            (_donor_context(b"one", unrelated=b"changed"),),
            unrelated_edit.dependencies,
        ) == (r"R:\source\include\common.h",)

        read_edit = probe_donor_transform_cache(
            lease,
            base_key=base,
            base_material=material,  # type: ignore[arg-type]
            contexts=(_donor_context(b"two", unrelated=b"changed"),),
        )
        assert read_edit.record is None
        assert read_edit.key != key
        assert read_edit.reason == "projected donor dependency content changed"


def test_compiler_hint_hit_and_header_change_miss(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    output = tmp_path / "unit.obj"
    output.write_bytes(b"object")
    cache = IncrementalCache(
        state,
        implementation=PRODUCER_CACHE_IMPLEMENTATION,
    )
    material = _material()
    base = compiler_base_key(material)  # type: ignore[arg-type]
    hint = _hint(base)
    reads = (
        ResolvedInclude(
            r"R:\source\src\unit.cpp",
            r"R:\source\src\unit.cpp",
            Digest.from_bytes(b"source"),
            6,
            IncludeOrigin.PROJECT_SOURCE,
            None,
        ),
        ResolvedInclude(
            "common.h",
            r"R:\source\include\common.h",
            Digest.from_bytes(b"one"),
            3,
            IncludeOrigin.PROJECT_SOURCE,
            0,
        ),
    )
    key = compiler_final_key(material, reads)  # type: ignore[arg-type]
    with cache.lease() as lease:
        record = lease.store(
            "producer",
            key,
            {"build/unit.obj": output},
            metadata=compiler_hint_metadata(hint),
        )
        lease.index_record("producer", "compiler-base", base, record)
        hit = probe_compiler_cache(
            lease,
            base_key=base,
            base_material=material,  # type: ignore[arg-type]
            expected_working_directory=r"R:\build",
            expected_source=r"R:\source\src\unit.cpp",
            include_directories=(r"R:\source\include",),
            environment_directories=(r"R:\source\include",),
            force_includes=(),
            authority=_authority(b"one"),
        )
        assert hit.record == record
        changed = probe_compiler_cache(
            lease,
            base_key=base,
            base_material=material,  # type: ignore[arg-type]
            expected_working_directory=r"R:\build",
            expected_source=r"R:\source\src\unit.cpp",
            include_directories=(r"R:\source\include",),
            environment_directories=(r"R:\source\include",),
            force_includes=(),
            authority=_authority(b"two"),
        )
        assert changed.record is None
        assert changed.key != key
        assert changed.reason == "recursive dependency content changed"


def test_shadow_ambiguity_and_malformed_hint_force_safe_miss(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    output = tmp_path / "unit.obj"
    output.write_bytes(b"object")
    cache = IncrementalCache(
        state,
        implementation=PRODUCER_CACHE_IMPLEMENTATION,
    )
    material = _material()
    base = compiler_base_key(material)  # type: ignore[arg-type]
    reads = (
        ResolvedInclude(
            r"R:\source\src\unit.cpp",
            r"R:\source\src\unit.cpp",
            Digest.from_bytes(b"source"),
            6,
            IncludeOrigin.PROJECT_SOURCE,
            None,
        ),
        ResolvedInclude(
            "common.h",
            r"R:\source\include\common.h",
            Digest.from_bytes(b"one"),
            3,
            IncludeOrigin.PROJECT_SOURCE,
            0,
        ),
    )
    key = compiler_final_key(material, reads)  # type: ignore[arg-type]
    with cache.lease() as lease:
        malformed = lease.store(
            "producer",
            key,
            {"build/unit.obj": output},
            metadata={"compiler_dependency_hint": {"schema": 99}},
        )
        lease.index_record("producer", "compiler-base", base, malformed)
        result = probe_compiler_cache(
            lease,
            base_key=base,
            base_material=material,  # type: ignore[arg-type]
            expected_working_directory=r"R:\build",
            expected_source=r"R:\source\src\unit.cpp",
            include_directories=(r"R:\source\include",),
            environment_directories=(r"R:\source\include",),
            force_includes=(),
            authority=_authority(b"one", shadow=True),
        )
        assert result.record is None
        assert result.key is None
        assert result.reason is not None


def test_valid_hint_shadow_ambiguity_forces_safe_miss(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    output = tmp_path / "unit.obj"
    output.write_bytes(b"object")
    cache = IncrementalCache(
        state,
        implementation=PRODUCER_CACHE_IMPLEMENTATION,
    )
    material = _material()
    base = compiler_base_key(material)  # type: ignore[arg-type]
    reads = (
        ResolvedInclude(
            r"R:\source\src\unit.cpp",
            r"R:\source\src\unit.cpp",
            Digest.from_bytes(b"source"),
            6,
            IncludeOrigin.PROJECT_SOURCE,
            None,
        ),
        ResolvedInclude(
            "common.h",
            r"R:\source\include\common.h",
            Digest.from_bytes(b"one"),
            3,
            IncludeOrigin.PROJECT_SOURCE,
            0,
        ),
    )
    key = compiler_final_key(material, reads)  # type: ignore[arg-type]
    with cache.lease() as lease:
        record = lease.store(
            "producer",
            key,
            {"build/unit.obj": output},
            metadata=compiler_hint_metadata(_hint(base)),
        )
        lease.index_record("producer", "compiler-base", base, record)
        result = probe_compiler_cache(
            lease,
            base_key=base,
            base_material=material,  # type: ignore[arg-type]
            expected_working_directory=r"R:\build",
            expected_source=r"R:\source\src\unit.cpp",
            include_directories=(r"R:\source\include",),
            environment_directories=(r"R:\source\include",),
            force_includes=(),
            authority=_authority(b"one", shadow=True),
        )
        assert result.record is None
        assert result.key is None
        assert result.reason is not None
        assert "resolves to 2" in result.reason


def test_probe_exhausts_history_and_reuses_validated_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    output = tmp_path / "unit.obj"
    output.write_bytes(b"object")
    cache = IncrementalCache(
        state,
        implementation=PRODUCER_CACHE_IMPLEMENTATION,
    )
    material = _material()
    base = compiler_base_key(material)  # type: ignore[arg-type]
    common_reads = (
        ResolvedInclude(
            r"R:\source\src\unit.cpp",
            r"R:\source\src\unit.cpp",
            Digest.from_bytes(b"source"),
            6,
            IncludeOrigin.PROJECT_SOURCE,
            None,
        ),
        ResolvedInclude(
            "common.h",
            r"R:\source\include\common.h",
            Digest.from_bytes(b"one"),
            3,
            IncludeOrigin.PROJECT_SOURCE,
            0,
        ),
    )
    common_key = compiler_final_key(material, common_reads)  # type: ignore[arg-type]
    source_only_hint = CompilerDependencyHint(
        base,
        r"R:\build",
        (MsvcSbrSource(r"R:\source\src\unit.cpp", None),),
    )
    stale_material = dict(material)
    stale_material["recursive_reads"] = [
        {
            "raw_path": "stale.h",
            "logical_path": r"R:\source\include\stale.h",
            "digest": "9" * 64,
            "size": 1,
            "origin": "project-source",
            "parent_index": 0,
        }
    ]
    stale_key = classic_cache_module.producer_cache_key(  # type: ignore[arg-type]
        stale_material
    )
    with cache.lease() as lease:
        older = lease.store(
            "producer",
            common_key,
            {"build/unit.obj": output},
            metadata=compiler_hint_metadata(_hint(base)),
        )
        lease.index_record("producer", "compiler-base", base, older)
        newer = lease.store(
            "producer",
            stale_key,
            {"build/unit.obj": output},
            metadata=compiler_hint_metadata(source_only_hint),
        )
        lease.index_record("producer", "compiler-base", base, newer)

        original_index = classic_cache_module.index_sealed_include_authority
        index_calls = 0

        def counted_index(authority: SealedIncludeAuthority) -> object:
            nonlocal index_calls
            index_calls += 1
            return original_index(authority)

        monkeypatch.setattr(
            classic_cache_module,
            "index_sealed_include_authority",
            counted_index,
        )
        result = probe_compiler_cache(
            lease,
            base_key=base,
            base_material=material,  # type: ignore[arg-type]
            expected_working_directory=r"R:\build",
            expected_source=r"R:\source\src\unit.cpp",
            include_directories=(r"R:\source\include",),
            environment_directories=(r"R:\source\include",),
            force_includes=(),
            authority=_authority(b"one"),
        )
        assert result.record == older
        assert result.key == common_key
        assert index_calls == 1

        class ValidatedOnlyLease:
            def __init__(self) -> None:
                self.lookups = 0

            def indexed_record_keys(self, *_args: object) -> tuple[str, ...]:
                return (older.key, *(f"{index:064x}" for index in range(1, 16)))

            def lookup(self, _domain: str, key: str) -> object:
                self.lookups += 1
                if self.lookups != 1 or key != older.key:
                    raise AssertionError("exact first candidate did not short-circuit history")
                return older

        lazy_lease = ValidatedOnlyLease()
        direct = probe_compiler_cache(
            lazy_lease,  # type: ignore[arg-type]
            base_key=base,
            base_material=material,  # type: ignore[arg-type]
            expected_working_directory=r"R:\build",
            expected_source=r"R:\source\src\unit.cpp",
            include_directories=(r"R:\source\include",),
            environment_directories=(r"R:\source\include",),
            force_includes=(),
            authority=_authority(b"one"),
        )
        assert direct.record == older
        assert lazy_lease.lookups == 1
