from __future__ import annotations

from types import MappingProxyType

import pytest

from reprobit.classic_includes import (
    IncludeOrigin,
    SealedIncludeAuthority,
    SealedIncludeFile,
)
from reprobit.classic_resources import (
    ClassicResourceDependencyError,
    ResourceReadKind,
    scan_msvc_resource_dependencies,
)
from reprobit.model import Digest


def _authority(payloads: dict[str, bytes]) -> SealedIncludeAuthority:
    return SealedIncludeAuthority(
        (r"R:\source", r"R:\toolchain"),
        tuple(
            SealedIncludeFile(
                path,
                Digest.from_bytes(payload),
                len(payload),
                (
                    IncludeOrigin.PROJECT_SOURCE
                    if path.casefold().startswith("r:\\source\\")
                    else IncludeOrigin.TOOLCHAIN_TREE
                ),
            )
            for path, payload in sorted(
                payloads.items(), key=lambda item: item[0].casefold()
            )
        ),
    )


def test_resource_scanner_closes_includes_conditionals_and_payloads() -> None:
    payloads = {
        r"R:\source\res\app.rc": (
            b'#include "resource.h"\n'
            b'#include <afxres.h>\n'
            b'#if FEATURE\nIDI_APP ICON DISCARDABLE "app.ico"\n#else\n'
            b'IDB_APP BITMAP "app.bmp"\n#endif\n'
        ),
        r"R:\source\res\resource.h": b"#define IDI_APP 1\n",
        r"R:\source\res\app.ico": b"icon",
        r"R:\source\res\app.bmp": b"bitmap",
        r"R:\toolchain\include\afxres.h": b'#include "winres.h"\n',
        r"R:\toolchain\include\winres.h": b"#define WIN32 1\n",
    }
    receipt = scan_msvc_resource_dependencies(
        source_path=r"R:\source\res\app.rc",
        include_directories=(r"R:\source",),
        environment_directories=(r"\toolchain\include",),
        authority=_authority(payloads),
        payloads=MappingProxyType(payloads),
    )

    assert receipt.source_path == r"R:\source\res\app.rc"
    assert {(item.logical_path, item.kind) for item in receipt.reads} == {
        (r"R:\source\res\app.rc", ResourceReadKind.ROOT),
        (r"R:\source\res\resource.h", ResourceReadKind.INCLUDE),
        (r"R:\toolchain\include\afxres.h", ResourceReadKind.INCLUDE),
        (r"R:\toolchain\include\winres.h", ResourceReadKind.INCLUDE),
        (r"R:\source\res\app.ico", ResourceReadKind.PAYLOAD),
        (r"R:\source\res\app.bmp", ResourceReadKind.PAYLOAD),
    }


@pytest.mark.parametrize(
    ("source", "message"),
    (
        (b"#include HEADER_NAME\n", "macro include"),
        (b'IDI_APP ICON ICON_NAME\n', "lacks a literal path"),
        (b'IDR_APP CUSTOM "payload.bin"\n', "unknown file-backed"),
        (b'#include "C:\\host\\escape.h"\n', "resolves to 0"),
        (b"#if FEATURE\n", "unterminated conditional"),
        (b'#rcinclude "hidden.rc2"\n', "unknown directive"),
    ),
)
def test_resource_scanner_rejects_unprovable_recursive_reads(
    source: bytes, message: str
) -> None:
    payloads = {r"R:\source\app.rc": source}

    with pytest.raises(ClassicResourceDependencyError, match=message):
        scan_msvc_resource_dependencies(
            source_path=r"R:\source\app.rc",
            include_directories=(),
            environment_directories=(),
            authority=_authority(payloads),
            payloads=payloads,
        )


def test_resource_scanner_rejects_payload_changed_after_authority_seal() -> None:
    sealed = {r"R:\source\app.rc": b"1 VERSIONINFO\n"}

    with pytest.raises(ClassicResourceDependencyError, match="changed after sealing"):
        scan_msvc_resource_dependencies(
            source_path=r"R:\source\app.rc",
            include_directories=(),
            environment_directories=(),
            authority=_authority(sealed),
            payloads={r"R:\source\app.rc": b"2 VERSIONINFO\n"},
        )
