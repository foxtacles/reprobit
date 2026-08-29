from __future__ import annotations

from pathlib import PureWindowsPath

import pytest

from reprobit.classic_includes import (
    ClassicIncludeTraceError,
    IncludeOrigin,
    MsvcSbrSource,
    MsvcSbrTrace,
    SealedIncludeAuthority,
    SealedIncludeFile,
    parse_msvc_sbr,
    resolve_msvc_include_trace,
    resolve_sealed_logical_read,
)
from reprobit.model import Digest


def _sbr(*sources: tuple[str, int | None], working: str = r"R:\build") -> bytes:
    payload = bytearray(b"\x00\x02\x00\x07\x00")
    payload.extend(working.encode("ascii") + b"\0")
    stack: list[int] = []
    for path, parent in sources:
        while stack and stack[-1] != parent:
            payload.append(10)
            stack.pop()
        if parent is not None and (not stack or stack[-1] != parent):
            raise AssertionError("fixture source parents must be depth-first")
        payload.append(1)
        payload.extend(path.encode("ascii") + b"\0")
        stack.append(len(stack))
    while stack:
        payload.append(10)
        stack.pop()
    return bytes(payload)


def _file(path: str, origin: IncludeOrigin) -> SealedIncludeFile:
    return SealedIncludeFile(path, Digest.from_bytes(path.encode()), len(path), origin)


def _authority(*files: SealedIncludeFile) -> SealedIncludeAuthority:
    return SealedIncludeAuthority(
        (r"R:\source", r"R:\toolchain"),
        tuple(sorted(files, key=lambda item: item.logical_path.casefold())),
    )


def test_vc4_sbr_parser_preserves_nested_source_ancestry() -> None:
    payload = _sbr(
        (r"R:\source\src\main.cpp", None),
        ("local.h", 0),
    )

    trace = parse_msvc_sbr(payload)

    assert trace.working_directory == r"R:\build"
    assert trace.sources == (
        MsvcSbrSource(r"R:\source\src\main.cpp", None),
        MsvcSbrSource("local.h", 0),
    )


@pytest.mark.parametrize(
    "payload",
    (
        b"not-an-sbr",
        b"\x00\x02\x00\x07\x00R:\\build\0\x01unterminated",
        b"\x00\x02\x00\x07\x00R:\\build\0\x0a",
        b"\x00\x02\x00\x07\x00R:\\build\0\xff",
    ),
)
def test_sbr_parser_rejects_wrong_truncated_and_unbalanced_streams(
    payload: bytes,
) -> None:
    with pytest.raises(ClassicIncludeTraceError):
        parse_msvc_sbr(payload)


def test_include_trace_resolves_only_unique_sealed_dos_paths() -> None:
    authority = _authority(
        _file(r"R:\source\src\main.cpp", IncludeOrigin.PROJECT_SOURCE),
        _file(r"R:\source\src\local.h", IncludeOrigin.PROJECT_SOURCE),
        _file(r"R:\toolchain\include\stdio.h", IncludeOrigin.TOOLCHAIN_TREE),
    )
    trace = MsvcSbrTrace(
        r"R:\build",
        (
            MsvcSbrSource(r"R:\source\src\main.cpp", None),
            MsvcSbrSource("local.h", 0),
            MsvcSbrSource("stdio.h", 0),
        ),
    )

    resolved = resolve_msvc_include_trace(
        trace,
        expected_working_directory=r"R:\build",
        expected_source=r"R:\source\src\main.cpp",
        include_directories=(r"R:\toolchain\include",),
        environment_directories=(),
        force_includes=(r"R:\source\src\local.h",),
        authority=authority,
    )

    assert [item.logical_path for item in resolved] == [
        r"R:\source\src\main.cpp",
        r"R:\source\src\local.h",
        r"R:\toolchain\include\stdio.h",
    ]
    assert [item.parent_index for item in resolved] == [None, 0, 0]


@pytest.mark.parametrize(
    "raw_path",
    (
        r"C:\host\escape.h",
        r"D:\mounted-volume\escape.h",
        r"\\server\share\escape.h",
        "/private/tmp/escape.h",
        r"R:\build\generated-host-copy.h",
    ),
)
def test_include_trace_rejects_host_other_drive_unc_and_build_paths(
    raw_path: str,
) -> None:
    authority = _authority(
        _file(r"R:\source\main.cpp", IncludeOrigin.PROJECT_SOURCE),
    )
    trace = MsvcSbrTrace(
        r"R:\build",
        (
            MsvcSbrSource(r"R:\source\main.cpp", None),
            MsvcSbrSource(raw_path, 0),
        ),
    )

    with pytest.raises(ClassicIncludeTraceError, match=r"resolves to 0|not a DOS path"):
        resolve_msvc_include_trace(
            trace,
            expected_working_directory=r"R:\build",
            expected_source=r"R:\source\main.cpp",
            include_directories=(),
            environment_directories=(),
            force_includes=(),
            authority=authority,
        )


def test_include_trace_rejects_ambiguous_recursive_header() -> None:
    authority = _authority(
        _file(r"R:\source\src\main.cpp", IncludeOrigin.PROJECT_SOURCE),
        _file(r"R:\source\src\shared.h", IncludeOrigin.PROJECT_SOURCE),
        _file(r"R:\toolchain\include\shared.h", IncludeOrigin.TOOLCHAIN_TREE),
    )
    trace = MsvcSbrTrace(
        r"R:\build",
        (
            MsvcSbrSource(r"R:\source\src\main.cpp", None),
            MsvcSbrSource("shared.h", 0),
        ),
    )

    with pytest.raises(ClassicIncludeTraceError, match="resolves to 2"):
        resolve_msvc_include_trace(
            trace,
            expected_working_directory=r"R:\build",
            expected_source=r"R:\source\src\main.cpp",
            include_directories=(r"R:\toolchain\include",),
            environment_directories=(),
            force_includes=(),
            authority=authority,
        )


def test_static_dependency_resolution_uses_declared_first_match_only_when_requested() -> None:
    authority = _authority(
        _file(r"R:\source\include\shared.h", IncludeOrigin.PROJECT_SOURCE),
        _file(r"R:\toolchain\include\shared.h", IncludeOrigin.TOOLCHAIN_TREE),
    )
    roots = (r"R:\source\include", r"R:\toolchain\include")

    with pytest.raises(ClassicIncludeTraceError, match="resolves to 2"):
        resolve_sealed_logical_read(
            "shared.h",
            search_roots=roots,
            authority=authority,
        )
    resolved = resolve_sealed_logical_read(
        "shared.h",
        search_roots=roots,
        authority=authority,
        first_match=True,
    )

    assert resolved.logical_path == r"R:\source\include\shared.h"


def test_include_authority_rejects_casefold_aliases() -> None:
    with pytest.raises(ClassicIncludeTraceError, match="DOS-case-colliding"):
        SealedIncludeAuthority(
            (r"R:\source",),
            (
                _file(r"R:\source\Header.h", IncludeOrigin.PROJECT_SOURCE),
                _file(r"R:\source\header.h", IncludeOrigin.PROJECT_SOURCE),
            ),
        )


def test_include_search_roots_must_be_sealed_even_on_native_windows() -> None:
    """The proof is DOS-native and never assumes winepath or host existence."""

    authority = _authority(
        _file(r"R:\source\main.cpp", IncludeOrigin.PROJECT_SOURCE),
    )
    trace = MsvcSbrTrace(r"R:\build", (MsvcSbrSource(r"R:\source\main.cpp", None),))

    with pytest.raises(ClassicIncludeTraceError, match="leaves sealed authority"):
        resolve_msvc_include_trace(
            trace,
            expected_working_directory=r"R:\build",
            expected_source=r"R:\source\main.cpp",
            include_directories=(r"C:\native-host-sdk\include",),
            environment_directories=(),
            force_includes=(),
            authority=authority,
        )
    assert PureWindowsPath(trace.working_directory).drive == "R:"


def test_forced_include_must_appear_in_complete_trace() -> None:
    authority = _authority(
        _file(r"R:\source\main.cpp", IncludeOrigin.PROJECT_SOURCE),
        _file(r"R:\source\forced.h", IncludeOrigin.PROJECT_SOURCE),
    )
    trace = MsvcSbrTrace(r"R:\build", (MsvcSbrSource(r"R:\source\main.cpp", None),))

    with pytest.raises(ClassicIncludeTraceError, match="forced include"):
        resolve_msvc_include_trace(
            trace,
            expected_working_directory=r"R:\build",
            expected_source=r"R:\source\main.cpp",
            include_directories=(r"R:\source",),
            environment_directories=(),
            force_includes=(r"R:\source\forced.h",),
            authority=authority,
        )
