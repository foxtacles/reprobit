#!/usr/bin/env python3
"""Build the repair sample's authenticated, normalized reference image."""

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
TARGET_SYMBOL = "_transform"
REFERENCE_BODY = Digest(value="0592ba1107856e319c261ed45129ab9b518486acbde960ada58b2ace9435ccfb")
REFERENCE_IMAGE = Digest(value="eef3d6d69f7b8db8666973ec6533a849fe5230e03b2d6c4a91053dc897a31f62")
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
        help="replace an existing reference after revalidating the new bytes",
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
    raise RuntimeError("this sample supports POSIX/Wine and native Windows")


def _run(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    environment: dict[str, str],
    label: str,
) -> None:
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
        raise RuntimeError(f"{label} failed:\n{completed.stdout}{completed.stderr}")


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
    state = DeclarationState(
        family=DeclarationFamily.DECLARATION_SHAPE,
        parameters=(
            DeclarationParameter(name="classes", value=1),
            DeclarationParameter(name="functions", value=10),
        ),
    )
    rendered = render_msvc_declaration_state(
        (SAMPLE_ROOT / "transform.cpp").read_bytes(),
        state,
    )
    if rendered.force_include is None:
        raise RuntimeError("reference compiler state did not render a force include")
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

    with tempfile.TemporaryDirectory(prefix="reprobit-repair-reference-") as raw_temporary:
        temporary_root = Path(raw_temporary)
        for name in (
            "home",
            "tmp",
            "xdg-runtime",
            "wine-prefix",
            "transform",
            "support",
            "link",
        ):
            (temporary_root / name).mkdir(mode=0o700)
        environment = _compiler_environment(toolchain_root, temporary_root)

        transform_root = temporary_root / "transform"
        (transform_root / "s.cpp").write_bytes(rendered.source)
        (transform_root / "run.h").write_bytes(rendered.force_include)
        shutil.copyfile(SAMPLE_ROOT / "shared.h", transform_root / "shared.h")
        _run(
            (
                os.fspath(driver),
                "/nologo",
                "/I.",
                "/Zi",
                "/O2",
                "/Ob1",
                "/FIrun.h",
                "/Foreference.obj",
                "/Fdreference.pdb",
                "/c",
                "s.cpp",
            ),
            cwd=transform_root,
            environment=environment,
            label="MSVC 4.2 reference compile",
        )
        reference_object = (transform_root / "reference.obj").read_bytes()
        function = MsvcFunctionReference.from_object(reference_object, TARGET_SYMBOL)
        if len(function.body) != 137 or Digest.from_bytes(function.body) != REFERENCE_BODY:
            raise RuntimeError("compiler did not reproduce the pinned reference function")

        support_root = temporary_root / "support"
        shutil.copyfile(SAMPLE_ROOT / "support.cpp", support_root / "support.cpp")
        shutil.copyfile(SAMPLE_ROOT / "shared.h", support_root / "shared.h")
        _run(
            (
                os.fspath(driver),
                "/nologo",
                "/I.",
                "/Zi",
                "/O2",
                "/Ob1",
                "/Fosupport.obj",
                "/Fdsupport.pdb",
                "/c",
                "support.cpp",
            ),
            cwd=support_root,
            environment=environment,
            label="MSVC 4.2 support compile",
        )

        link_root = temporary_root / "link"
        (link_root / "reference.obj").write_bytes(reference_object)
        shutil.copyfile(support_root / "support.obj", link_root / "support.obj")
        _run(
            (
                os.fspath(linker),
                "/nologo",
                "/nodefaultlib",
                "/entry:transform",
                "/subsystem:console",
                "/include:_support_marker",
                "/out:raw-reference.exe",
                "reference.obj",
                "support.obj",
            ),
            cwd=link_root,
            environment=environment,
            label="MSVC 4.2 reference link",
        )
        raw_image = (link_root / "raw-reference.exe").read_bytes()
        image, _proof = apply_pe_metadata_candidate(
            raw_image,
            {"link_time": 0, "resource_time": 0},
        )

    if len(image) != REFERENCE_IMAGE_SIZE or Digest.from_bytes(image) != REFERENCE_IMAGE:
        raise RuntimeError("normalized reference image differs from its pinned provenance")
    _publish(
        SAMPLE_ROOT / "reference" / "repair.exe",
        image,
        replace=args.replace,
    )
    print(f"prepared reference/repair.exe ({REFERENCE_IMAGE.value})")


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
