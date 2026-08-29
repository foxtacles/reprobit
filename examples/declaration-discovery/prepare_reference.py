#!/usr/bin/env python3
"""Build this example's local reference object with MSVC 4.2."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import cast

from reprobit.discovery_contracts import (
    DeclarationFamily,
    DeclarationState,
    enumerate_declaration_states,
)
from reprobit.model import Digest
from reprobit.msvc_compile import DirectMsvcCompiler, render_msvc_declaration_state
from reprobit.msvc_discovery import MsvcDiscoveryRequest
from reprobit.toolchains import MSVC_42, ClassicMSVCToolchain

SAMPLE_ROOT = Path(__file__).resolve().parent


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build the declaration-discovery example's local reference.obj "
            "with an archaic-msvc 4.2 installation."
        )
    )
    parser.add_argument(
        "--toolchain-root",
        type=Path,
        default=os.environ.get("REPROBIT_MSVC_4_2_ROOT"),
        required="REPROBIT_MSVC_4_2_ROOT" not in os.environ,
        help=(
            "MSVC 4.2 installation (default: REPROBIT_MSVC_4_2_ROOT when set)"
        ),
    )
    parser.add_argument(
        "--request",
        type=Path,
        default=SAMPLE_ROOT / "campaign.json",
        help="campaign request whose source and compiler arguments should be used",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="reference object path (default: the request's reference object)",
    )
    parser.add_argument(
        "--matching-classes",
        type=int,
        default=3,
        help="generated class count used for the reference (default: 3)",
    )
    parser.add_argument(
        "--matching-functions",
        type=int,
        default=10,
        help="generated function count used for the reference (default: 10)",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help="replace a different existing reference object",
    )
    return parser


def _matching_state(
    request: MsvcDiscoveryRequest,
    classes: int,
    functions: int,
) -> DeclarationState:
    matches = tuple(
        state
        for state in enumerate_declaration_states(request.plan)
        if state.family is DeclarationFamily.DECLARATION_SHAPE
        and state.parameter("classes") == classes
        and state.parameter("functions") == functions
    )
    if len(matches) != 1:
        raise RuntimeError(
            "campaign contains "
            f"{len(matches)} declaration-shape states with classes={classes}, "
            f"functions={functions}"
        )
    return matches[0]


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
                        os.fspath(Path(wineserver).resolve(strict=True).parent),
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


def _build_reference(args: argparse.Namespace) -> Path:
    request_path = cast(Path, args.request).expanduser().resolve(strict=True)
    request = MsvcDiscoveryRequest.model_validate_json(request_path.read_bytes())
    if len(request.references) != 1:
        raise RuntimeError("this example expects exactly one reference object")
    source_path = (request_path.parent / request.source).resolve(strict=True)
    source = source_path.read_bytes()
    output_argument = cast(Path | None, args.output)
    output = (
        output_argument.expanduser()
        if output_argument is not None
        else request_path.parent / request.references[0].object
    ).resolve(strict=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        if output.is_symlink() or not output.is_file():
            raise RuntimeError(f"output is not a regular file: {output}")
        if not cast(bool, args.replace):
            print(f"reference already exists; left unchanged: {output}")
            print("use --replace after intentionally changing the source or campaign")
            return output

    toolchain_root = cast(Path, args.toolchain_root).expanduser().resolve(strict=True)
    ClassicMSVCToolchain(MSVC_42, toolchain_root).doctor().require_ok()
    driver = (
        toolchain_root / "wine" / "x86" / "cl"
        if os.name == "posix"
        else toolchain_root / "bin" / "CL.EXE"
    )
    state = _matching_state(
        request,
        cast(int, args.matching_classes),
        cast(int, args.matching_functions),
    )

    with tempfile.TemporaryDirectory(
        prefix="reprobit-reference-",
        dir=output.parent,
    ) as raw_temporary:
        temporary_root = Path(raw_temporary)
        for name in ("home", "tmp", "xdg-runtime", "wine-prefix", "compile"):
            (temporary_root / name).mkdir(mode=0o700)
        compiler = DirectMsvcCompiler.create(
            wrapper=driver,
            arguments=request.compiler_arguments,
            environment=_compiler_environment(toolchain_root, temporary_root),
            toolchain_authority=Digest.from_path(toolchain_root / "bin" / "CL.EXE"),
        )
        built = compiler.compile(
            render_msvc_declaration_state(source, state),
            temporary_root / "compile",
        ).object_path.read_bytes()

    temporary_output = output.with_name(f".{output.name}.new")
    temporary_output.write_bytes(built)
    temporary_output.replace(output)
    print(f"prepared local reference: {output}")
    print(
        "matching declaration shape: "
        f"{cast(int, args.matching_classes)} classes, "
        f"{cast(int, args.matching_functions)} functions"
    )
    print(f"sha256: {Digest.from_bytes(built).value}")
    return output


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        _build_reference(args)
    except (OSError, RuntimeError, ValueError) as exc:
        parser.exit(2, f"prepare_reference.py: error: {exc}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
