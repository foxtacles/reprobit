"""Live map evidence excludes dead COMDATs and never guesses a provider."""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest
from test_repair_census import OBJECT, PLAN, SOURCE, _bundle

from reprobit.classic.pe_metadata import apply_pe_metadata_candidate
from reprobit.classic_incremental_context import SeedObject
from reprobit.composition_ledger import ProvidedObject, build_ledger, function_bodies
from reprobit.linker_map import LinkerMapError, live_public_providers
from reprobit.repair_census import plan_repair_census
from reprobit.toolchains import MSVC_42, ClassicMSVCToolchain


def _map(*rows: str) -> bytes:
    return (
        " Address Publics by Value Rva+Base Lib:Object\n"
        + "\n".join(rows)
        + "\n entry point at 0001:00000000\n"
    ).encode("ascii")


def _coff(functions: tuple[tuple[str, bytes], ...]) -> bytes:
    offset = 20 + 40 * len(functions)
    raw = b"".join(body for _, body in functions)
    headers = b""
    symbols = b""
    for index, (name, body) in enumerate(functions, 1):
        assert len(name) <= 8
        headers += b".text\0\0\0" + struct.pack(
            "<IIIIIIHHI", 0, 0, len(body), offset, 0, 0, 0, 0, 0x60501020
        )
        auxiliary = struct.pack("<IHHIHB3s", len(body), 0, 0, 0, 0, 2, b"\0" * 3)
        symbols += b".text\0\0\0" + struct.pack("<IhHBB", 0, index, 0, 3, 1) + auxiliary
        symbols += name.encode().ljust(8, b"\0") + struct.pack("<IhHBB", 0, index, 0x20, 2, 0)
        offset += len(body)
    return (
        struct.pack("<HHIIIHH", 0x14C, len(functions), 0, offset, len(functions) * 3, 0, 0)
        + headers
        + raw
        + symbols
        + struct.pack("<I", 4)
    )


BEFORE = _coff((("_live", b"\x31\xc0\xc3"), ("_dead", b"\x90\x90\xc3")))
AFTER = _coff((("_live", b"\x31\xc0\xc3"),))


def _census(map_payload: bytes):  # type: ignore[no-untyped-def]
    selected = live_public_providers(map_payload, {"unit.obj": frozenset({OBJECT})})
    ledger = build_ledger(
        "0" * 64,
        {"program": (ProvidedObject(OBJECT, function_bodies(BEFORE), PLAN.id),)},
        {"program": selected},
    )
    assert set(ledger.targets["program"].functions) == {"_live"}
    return plan_repair_census(
        _bundle(),
        ledger,
        {"compiler.unit": SeedObject("compiler.unit", SOURCE, OBJECT, "program", AFTER)},
    )


def test_removed_dead_comdat_does_not_enter_repair_census() -> None:
    census = _census(_map(" 0001:00000000 _live 00401000 f unit.obj"))
    assert census.entries == census.missing == census.refusals == ()


def test_map_never_substitutes_a_project_definition_for_an_external_winner() -> None:
    assert (
        live_public_providers(
            _map(" 0001:00000000 _live 00401000 f msvcrt:helper.obj"),
            {"unit.obj": frozenset({OBJECT})},
            external_archives=frozenset({"msvcrt"}),
        )
        == {}
    )
    with pytest.raises(LinkerMapError, match="not an admitted input"):
        live_public_providers(
            _map(" 0001:00000000 _live 00401000 f unseen.obj"),
            {"unit.obj": frozenset({OBJECT})},
        )


@pytest.mark.parametrize("provider", ["unit.obj", "core:unit.obj"])
def test_map_refuses_ambiguous_object_or_archive_member_basenames(provider: str) -> None:
    with pytest.raises(LinkerMapError, match="ambiguous"):
        live_public_providers(
            _map(f" 0001:00000000 _live 00401000 f {provider}"),
            {provider: frozenset({"build/a/unit.obj", "build/b/unit.obj"})},
        )


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b" Address Publics by Value Rva+Base Lib:Object\n",
        _map(" 0001:00000000 _live 00401000 "),
        _map(" 0001:00000000 _live 00401000 f"),
        _map(" malformed row"),
        _map(
            " 0001:00000000 _live 00401000 f unit.obj", " 0001:00000000 _live 00401000 f unit.obj"
        ),
    ],
)
def test_map_rejects_malformed_or_truncated_evidence(payload: bytes) -> None:
    with pytest.raises(LinkerMapError):
        live_public_providers(payload, {"unit.obj": frozenset({OBJECT})})


@pytest.mark.msvc42
@pytest.mark.skipif(
    not os.environ.get("REPROBIT_MSVC_4_2_ROOT"), reason="requires authenticated MSVC4.2"
)
def test_real_linker_map_excludes_a_removed_comdat_without_changing_image(tmp_path: Path) -> None:
    root = Path(os.environ["REPROBIT_MSVC_4_2_ROOT"]).resolve(strict=True)
    ClassicMSVCToolchain(MSVC_42, root).doctor().require_ok()
    environment = os.environ.copy()
    if os.name == "posix":
        if shutil.which("wine") is None or shutil.which("wineserver") is None:
            pytest.skip("requires Wine")
        command = (str(root / "wine/x86/link"),)
        environment.update(WINEPREFIX=str(tmp_path / "prefix"), WINEDEBUG="-all")
    else:
        command = (str(root / "bin/LINK.EXE"),)
    images: list[bytes] = []
    maps: list[bytes] = []
    try:
        for index, (payload, map_enabled) in enumerate(
            ((BEFORE, True), (AFTER, True), (BEFORE, False))
        ):
            case = tmp_path / str(index)
            case.mkdir()
            (case / "unit.obj").write_bytes(payload)
            args = (
                *command,
                "/NOLOGO",
                "/MACHINE:IX86",
                "/ENTRY:live",
                "/SUBSYSTEM:CONSOLE",
                "/NODEFAULTLIB",
                "/FIXED",
                "/OPT:REF",
                "/OUT:image.exe",
                "unit.obj",
            )
            if map_enabled:
                args = (*args, "/MAP:image.map")
            result = subprocess.run(
                args, cwd=case, env=environment, capture_output=True, timeout=60
            )
            assert result.returncode == 0, result.stdout + result.stderr
            image, _audit = apply_pe_metadata_candidate(
                (case / "image.exe").read_bytes(), {"link_time": 0, "resource_time": 0}
            )
            images.append(image)
            if map_enabled:
                maps.append((case / "image.map").read_bytes())
    finally:
        if os.name == "posix":
            subprocess.run(("wineserver", "-k"), env=environment, capture_output=True, timeout=15)
    assert images[0] == images[1] == images[2]
    for payload in maps:
        assert b"_dead" not in payload
        census = _census(payload)
        assert census.entries == census.missing == census.refusals == ()


def test_project_and_external_archive_name_collision_is_not_project_evidence() -> None:
    with pytest.raises(LinkerMapError, match="archive identity is ambiguous"):
        live_public_providers(
            _map(" 0001:00000000 _live 00401000 f core:unit.obj"),
            {"core:unit.obj": frozenset({OBJECT})},
            ambiguous_archives=frozenset({"core"}),
        )
