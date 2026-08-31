#!/usr/bin/env python3
"""Build two project-owned reference objects and their normalized executable."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from reprobit.classic.pe_metadata import apply_pe_metadata_candidate
from reprobit.discovery_contracts import (
    DeclarationFamily,
    DeclarationParameter,
    DeclarationState,
)
from reprobit.model import Digest
from reprobit.msvc_compile import render_msvc_declaration_state
from reprobit.msvc_discovery_coff import MsvcFunctionReference
from reprobit.toolchains import MSVC_42, ClassicMSVCToolchain
from reprobit.user_config import resolve_toolchain_root

SAMPLE_ROOT = Path(__file__).resolve().parent
SOURCES = (
    ("transform_one.cpp", "_transform_one"),
    ("transform_two.cpp", "_transform_two"),
)
REFERENCE_STATE = DeclarationState(
    family=DeclarationFamily.DECLARATION_SHAPE,
    parameters=(
        DeclarationParameter(name="classes", value=1),
        DeclarationParameter(name="functions", value=10),
    ),
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--toolchain-root",
        type=Path,
        help="compiler installation override (normally remembered by rbit setup)",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help="replace existing generated reference files after rebuilding them",
    )
    return parser


def _environment(toolchain_root: Path, temporary: Path) -> dict[str, str]:
    if os.name == "posix":
        wine = shutil.which("wine")
        wineserver = shutil.which("wineserver")
        if wine is None or wineserver is None:
            raise RuntimeError("Wine and wineserver must both be available on PATH")
        return {
            "HOME": os.fspath(temporary / "home"),
            "USER": "reprobit",
            "LOGNAME": "reprobit",
            "TMPDIR": os.fspath(temporary / "tmp"),
            "XDG_RUNTIME_DIR": os.fspath(temporary / "xdg-runtime"),
            "WINEPREFIX": os.fspath(temporary / "wine-prefix"),
            "PATH": os.pathsep.join(
                dict.fromkeys(
                    (
                        os.fspath(Path(wine).resolve(strict=True).parent),
                        "/usr/bin",
                        "/bin",
                        "/usr/sbin",
                        "/sbin",
                    )
                )
            ),
            "LC_ALL": "C",
            "LANG": "C",
            "WINEDEBUG": "-all",
            "MVK_CONFIG_LOG_LEVEL": "0",
        }
    if os.name == "nt":
        system_root = os.environ.get("SYSTEMROOT")
        if system_root is None:
            raise RuntimeError("native Windows has no SYSTEMROOT environment")
        return {
            "SYSTEMROOT": system_root,
            "TEMP": os.fspath(temporary / "tmp"),
            "TMP": os.fspath(temporary / "tmp"),
            "PATH": os.pathsep.join(
                (os.fspath(toolchain_root / "bin"), os.fspath(Path(system_root) / "System32"))
            ),
            "INCLUDE": os.pathsep.join(
                (
                    os.fspath(toolchain_root / "include"),
                    os.fspath(toolchain_root / "mfc" / "include"),
                )
            ),
            "LIB": os.pathsep.join(
                (
                    os.fspath(toolchain_root / "lib"),
                    os.fspath(toolchain_root / "mfc" / "lib"),
                )
            ),
        }
    raise RuntimeError("this example supports POSIX/Wine and native Windows")


def _run(argv: tuple[str, ...], *, cwd: Path, environment: dict[str, str]) -> None:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"tool exited with {completed.returncode}: {' '.join(argv)}\n"
            + completed.stdout
            + completed.stderr
        )


def _publish(path: Path, payload: bytes, *, replace: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not replace:
        if path.is_symlink() or not path.is_file() or path.read_bytes() != payload:
            raise RuntimeError(f"different reference already exists: {path}")
        return
    temporary = path.with_name(f".{path.name}.new")
    temporary.write_bytes(payload)
    temporary.replace(path)


def _prepare(args: argparse.Namespace) -> None:
    toolchain_root = resolve_toolchain_root(MSVC_42, args.toolchain_root)
    ClassicMSVCToolchain(MSVC_42, toolchain_root).doctor().require_ok()
    driver = (
        toolchain_root / "wine" / "x86" / "cl"
        if os.name == "posix"
        else toolchain_root / "bin" / "CL.EXE"
    )
    linker = (
        toolchain_root / "wine" / "x86" / "link"
        if os.name == "posix"
        else toolchain_root / "bin" / "LINK.EXE"
    )
    objects: list[tuple[str, bytes]] = []
    with tempfile.TemporaryDirectory(prefix="reprobit-grind-progress-") as value:
        temporary = Path(value)
        for name in ("home", "tmp", "xdg-runtime", "wine-prefix", "link"):
            (temporary / name).mkdir(mode=0o700)
        environment = _environment(toolchain_root, temporary)
        for index, (source_name, symbol) in enumerate(SOURCES, start=1):
            source = (SAMPLE_ROOT / source_name).read_bytes()
            rendered = render_msvc_declaration_state(source, REFERENCE_STATE)
            if rendered.force_include is None:
                raise RuntimeError("reference declaration state did not produce an include")
            compile_root = temporary / f"compile-{index}"
            compile_root.mkdir(mode=0o700)
            (compile_root / "unit.cpp").write_bytes(rendered.source)
            (compile_root / "state.h").write_bytes(rendered.force_include)
            _run(
                (
                    os.fspath(driver),
                    "/nologo",
                    "/I.",
                    "/Zi",
                    "/O2",
                    "/Ob1",
                    "/FIstate.h",
                    "/Fooutput.obj",
                    "/Fdoutput.pdb",
                    "/c",
                    "unit.cpp",
                ),
                cwd=compile_root,
                environment=environment,
            )
            payload = (compile_root / "output.obj").read_bytes()
            reference = MsvcFunctionReference.from_object(payload, symbol)
            if not reference.body:
                raise RuntimeError(f"compiler emitted an empty reference function: {symbol}")
            object_name = f"{Path(source_name).stem}.obj"
            objects.append((object_name, payload))
            (temporary / "link" / object_name).write_bytes(payload)

        _run(
            (
                os.fspath(linker),
                "/nologo",
                "/nodefaultlib",
                "/entry:transform_one",
                "/include:_transform_two",
                "/subsystem:console",
                "/out:raw-reference.exe",
                *(name for name, _payload in objects),
            ),
            cwd=temporary / "link",
            environment=environment,
        )
        raw_image = (temporary / "link" / "raw-reference.exe").read_bytes()
        image, _proof = apply_pe_metadata_candidate(
            raw_image,
            {"link_time": 0, "resource_time": 0},
        )

    for name, payload in objects:
        _publish(SAMPLE_ROOT / "reference" / name, payload, replace=args.replace)
        print(f"prepared reference/{name}")
    _publish(
        SAMPLE_ROOT / "reference" / "grind-progress.exe",
        image,
        replace=args.replace,
    )
    print(f"prepared reference/grind-progress.exe ({Digest.from_bytes(image).value})")


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        _prepare(args)
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
        parser.exit(2, f"prepare_reference.py: error: {exc}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
