#!/usr/bin/env python3
"""Build the grind example's local reference object and normalized PE."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import cast

from reprobit.classic.pe_metadata import apply_pe_metadata_candidate
from reprobit.discovery_contracts import (
    DeclarationFamily,
    DeclarationState,
    enumerate_declaration_states,
)
from reprobit.discovery_project import ProjectGrindPlan
from reprobit.model import Digest
from reprobit.msvc_compile import render_msvc_declaration_state
from reprobit.msvc_discovery_analysis import MsvcFunctionReference
from reprobit.toolchains import MSVC_42, ClassicMSVCToolchain
from reprobit.user_config import resolve_toolchain_root

SAMPLE_ROOT = Path(__file__).resolve().parent
TARGET_SYMBOL = "_transform"
REFERENCE_BODY = Digest(value="0592ba1107856e319c261ed45129ab9b518486acbde960ada58b2ace9435ccfb")
REFERENCE_IMAGE = Digest(value="9c78bd9cfe3c8ded8a9a587165237d2a394719b48be34021a3cb09aff8220aab")
REFERENCE_IMAGE_SIZE = 1536


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
        help="replace existing generated reference files after revalidating them",
    )
    return parser


def _compiler_environment(toolchain_root: Path, temporary_root: Path) -> dict[str, str]:
    if os.name == "posix":
        wine = shutil.which("wine")
        wineserver = shutil.which("wineserver")
        if wine is None or wineserver is None:
            raise RuntimeError("Wine and wineserver must both be available on PATH")
        return {
            "HOME": os.fspath(temporary_root / "home"),
            "USER": "reprobit",
            "LOGNAME": "reprobit",
            "TMPDIR": os.fspath(temporary_root / "tmp"),
            "XDG_RUNTIME_DIR": os.fspath(temporary_root / "xdg-runtime"),
            "WINEPREFIX": os.fspath(temporary_root / "wine-prefix"),
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
            "TEMP": os.fspath(temporary_root / "tmp"),
            "TMP": os.fspath(temporary_root / "tmp"),
            "PATH": os.pathsep.join(
                (
                    os.fspath(toolchain_root / "bin"),
                    os.fspath(Path(system_root) / "System32"),
                )
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


def _state(config: ProjectGrindPlan) -> DeclarationState:
    for search in config.plan.searches:
        if search.family is DeclarationFamily.DECLARATION_SHAPE:
            matches = tuple(
                state
                for state in enumerate_declaration_states(config.plan)
                if state.family is DeclarationFamily.DECLARATION_SHAPE
                and state.parameter("classes") == 1
                and state.parameter("functions") == 10
            )
            if len(matches) == 1:
                return matches[0]
    raise RuntimeError("campaign does not contain exactly one classes=1, functions=10 state")


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
    config = ProjectGrindPlan.model_validate_json(
        (SAMPLE_ROOT / "reprobit" / "discovery.json").read_bytes()
    )
    source = (SAMPLE_ROOT / "transform.cpp").read_bytes()
    state = _state(config)
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
    with tempfile.TemporaryDirectory(prefix="reprobit-grind-reference-") as raw_temporary:
        temporary_root = Path(raw_temporary)
        for name in (
            "home",
            "tmp",
            "xdg-runtime",
            "wine-prefix",
            "compile",
            "link",
        ):
            (temporary_root / name).mkdir(mode=0o700)
        environment = _compiler_environment(toolchain_root, temporary_root)
        rendered = render_msvc_declaration_state(source, state)
        if rendered.force_include is None:
            raise RuntimeError("reference declaration state did not render a force include")
        compile_root = temporary_root / "compile"
        (compile_root / "s.cpp").write_bytes(rendered.source)
        (compile_root / "run.h").write_bytes(rendered.force_include)
        compiled = subprocess.run(
            (
                os.fspath(driver),
                "/nologo",
                "/I.",
                "/Zi",
                "/O2",
                "/Ob1",
                "/FIrun.h",
                "/Foo.obj",
                "/Fdo.pdb",
                "/c",
                "s.cpp",
            ),
            cwd=compile_root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if compiled.returncode != 0:
            raise RuntimeError(
                "MSVC 4.2 reference compile failed:\n" + compiled.stdout + compiled.stderr
            )
        built_object = (compile_root / "o.obj").read_bytes()
        reference = MsvcFunctionReference.from_object(built_object, TARGET_SYMBOL)
        if len(reference.body) != 137 or Digest.from_bytes(reference.body) != REFERENCE_BODY:
            raise RuntimeError("compiler did not reproduce the pinned reference function")
        object_path = temporary_root / "link" / "reference.obj"
        object_path.write_bytes(built_object)
        completed = subprocess.run(
            (
                os.fspath(linker),
                "/nologo",
                "/nodefaultlib",
                "/entry:transform",
                "/subsystem:console",
                "/out:raw-reference.exe",
                "reference.obj",
            ),
            cwd=temporary_root / "link",
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if completed.returncode != 0:
            raise RuntimeError("MSVC 4.2 linker failed:\n" + completed.stdout + completed.stderr)
        raw_image = (temporary_root / "link" / "raw-reference.exe").read_bytes()
        image, _proof = apply_pe_metadata_candidate(
            raw_image,
            {"link_time": 0, "resource_time": 0},
        )
    if len(image) != REFERENCE_IMAGE_SIZE or Digest.from_bytes(image) != REFERENCE_IMAGE:
        raise RuntimeError("normalized reference image differs from its pinned provenance")
    _publish(
        SAMPLE_ROOT / "reference" / "reference.obj",
        built_object,
        replace=cast(bool, args.replace),
    )
    _publish(
        SAMPLE_ROOT / "reference" / "grind.exe",
        image,
        replace=cast(bool, args.replace),
    )
    print("prepared reference/reference.obj")
    print(f"prepared reference/grind.exe ({REFERENCE_IMAGE.value})")


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
