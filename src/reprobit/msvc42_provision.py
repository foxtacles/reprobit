"""Provision the finite MSVC 4.2 authority used by ReproBit.

The compiler payload remains external to ReproBit.  This module checks out two
immutable Archaic MSVC revisions, copies only the admitted files and input
trees, applies the required C2 patch, adds ReproBit's redistributable POSIX
transport snapshot, and authenticates the result before an atomic publication.
It intentionally does not cache or redistribute the Microsoft payload.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from reprobit.assets import runtime_asset_directory
from reprobit.toolchains import MSVC_42, portable_tree_receipt, profile

_PROFILE = profile(MSVC_42)
_MSVC420_SOURCE = _PROFILE.source_for_path("bin/CL.EXE")
_MSVC500_SOURCE = _PROFILE.source_for_path("bin/MSVCRT40.dll")
MSVC420_REPOSITORY = _MSVC420_SOURCE.repository
MSVC420_REVISION = _MSVC420_SOURCE.revision
MSVC500_REPOSITORY = _MSVC500_SOURCE.repository
MSVC500_REVISION = _MSVC500_SOURCE.revision


class ProvisionError(RuntimeError):
    """The external toolchain could not be reproduced exactly."""


@dataclass(frozen=True, slots=True)
class FileAuthority:
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class TreeAuthority:
    entries: int
    max_depth: int
    membership_sha256: str
    content_sha256: str


_FILES = {
    "bin/CL.EXE": FileAuthority(
        37_888, "c5bf7ad84482e8a54d5753fcbd3e648d8a1192f5ca8b8cf1f5d23b651750585f"
    ),
    "bin/C1.EXE": FileAuthority(
        408_576, "c5a62937d806fbd8663b05f15bd02670a43bdf983a50ee4080bcfd90a7643b90"
    ),
    "bin/C1XX.EXE": FileAuthority(
        793_088, "9e0782ec157b30a387ca855374bc4c1b8a605dfb12364425497ba431541a5bf9"
    ),
    "bin/C2.EXE": FileAuthority(
        549_888, "2aa1fcace0779531b3ec80b730663acd98f181aed3cdff51366440c602b724b5"
    ),
    "bin/MSPDB41.DLL": FileAuthority(
        271_872, "6cab17cfcbc5a6317ab030a0db99164cafdfd1f360baa36186849237ffb25858"
    ),
    "bin/LINK.EXE": FileAuthority(
        514_048, "6ca5a19155e4170e8df08247769b4586fa951743f09f1d8fcec838fc4eb9750e"
    ),
    "bin/LIB.EXE": FileAuthority(
        5_632, "9d840e99a7e7f23f06d77b3667747a2d814419d17b53b437b895fd622894cbd4"
    ),
    "bin/RC.EXE": FileAuthority(
        16_432, "a99c2a9da4744f831539dcec1f6a7219046c0295ebcff8eff46ec7b0f5b21101"
    ),
    "bin/RCDLL.DLL": FileAuthority(
        112_560, "21d47edc33dccba245fa5a4c00688fe4539f160cbecff650352b5f2dcf9a14b8"
    ),
    "bin/CVTRES.EXE": FileAuthority(
        14_000, "7d66e9e5437b8d983432d8addedd7ea342bb814a34b1ffdebbc30018485004e8"
    ),
    "bin/MSVCRT40.dll": FileAuthority(
        326_656, "ab55a2de2b6faf3daacd3e69473d385ceaead8033f7c79beb6bbf802f230f030"
    ),
    "bin/msvcrt20.dll": FileAuthority(
        253_952, "72a46bd99188b67d48270a1bf40ffd6cd9bc5814818066a743eaffb8d64d88e8"
    ),
    "lib/MSVCRT.LIB": FileAuthority(
        517_150, "9aa05fde8340c02f5365ee04a0d7b4e782abc26e5439772a8efe80c79c17c9f4"
    ),
}

# Optional native Windows build-system frontend. Certifying builds and general
# compiler setup do not require it; provisioning includes it for CMake imports.
_CMAKE_FRONTEND_FILES = {
    "bin/NMAKE.EXE": FileAuthority(
        61_952, "2992db8eca994af6a7d7108c20d3976ae1d8b0b6e4923bd8de3ec59f24f91113"
    ),
    "bin/NMAKE.ERR": FileAuthority(
        5_097, "85c92a5904ea82b88bca4b01004cab2c52712a1fa7e073f0032106127f653ebc"
    ),
}

# These are host-side, permissively licensed shell transports versioned and
# distributed with ReproBit.  They are deliberately outside profile_sources:
# compiler/runtime/header/library payload still comes only from the two pinned
# archaic-msvc repositories above.  Keeping their installed bytes fixed lets a
# project use one toolchain lock on POSIX and native Windows.
_TRANSPORT_FILES = {
    "wine/x86/cl": FileAuthority(
        2_900, "01f87f5c7532cc8d0a1fefcbb28031924b718d31c8172949630b5384a51c232d"
    ),
    "wine/x86/rc": FileAuthority(
        940, "185d8d83fa318273a02a50dfa8fbbadc2f02607d0da8d81263e740747485e58d"
    ),
    "wine/x86/link": FileAuthority(
        944, "e1a319a1c69d3b4718d26bae58b3369e37a9275cf03dcf1c61ae339cb08a3014"
    ),
    "wine/x86/lib": FileAuthority(
        942, "666710820b68ead0c5be94f2b53f1737146ab59b125719c3ed8333ea71b80d67"
    ),
    "wine/x86/wine-msvc.sh": FileAuthority(
        4_086, "13663766b596946d429c9340976ff75cf9955b7664f5d59ffd49edaf30fe5b8d"
    ),
}

# The locked selector scripts source this during one-off CMake graph
# configuration.  Direct authenticated builds execute wine-msvc.sh through
# ReproBit's own proxy, so projects do not need to add this support file to
# their portable lock; the provisioner still authenticates it.
_TRANSPORT_SUPPORT_FILES = {
    "wine/x86/msvcenv.sh": FileAuthority(
        2_476, "6b0bb938c6132039ca2e754528b8a0ecb87af14002ccb19c420b33c00dc71c22"
    )
}
_PROVISIONED_TRANSPORT_FILES = {**_TRANSPORT_FILES, **_TRANSPORT_SUPPORT_FILES}

_TREES = {
    "include": TreeAuthority(
        401,
        1,
        "871b510d5aeb49111ca0369fa44559d8fb2592a6a355b78732d5d558cdc1a0ac",
        "218544d0304ada1057164e1eb3ae14001d27d14e60899c2f145321bcbdabe358",
    ),
    "mfc/include": TreeAuthority(
        133,
        1,
        "b9b17eb5adb476049f6467285feb0d9b5c5f766a075cc07eaf2a7bcb98206abd",
        "336f6028d6bf40ed5b00e8256d96477e386aca5d1eef497abd289a038fea94cf",
    ),
    "lib": TreeAuthority(
        116,
        0,
        "fd7038f61b3e1217edf2acdecbc7b85ba910f578b6fed85aefb2acfcb3b79968",
        "c35374963fa52f92baefbe7623dc2c82057342acc3d5ae231598b01ca7f82595",
    ),
    "mfc/lib": TreeAuthority(
        20,
        0,
        "b224cf66b687b10ddd2a02eee5c10a8463e0f111284973ade2e5111ba6911bcd",
        "64f6606ed9b4e2d52d6dbe7c88c04dc8f163e0522eb315d46b63c1a7b6bf8c8c",
    ),
}

_C2_UPSTREAM = FileAuthority(
    549_888,
    "674fb9e410481378c6980c3f21914e513128c85001e8337aca73b587b6273ae9",
)
_C2_PATCHES = (
    (0x52F07, bytes.fromhex("e8 4f b3 fe ff"), b"\x90" * 5),
    (0x74832, bytes.fromhex("e8 24 9a fc ff"), b"\x90" * 5),
)


ProgressCallback = Callable[[str], None]


def _emit(progress: ProgressCallback | None, message: str) -> None:
    if progress is not None:
        progress(message)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_file(path: Path, authority: FileAuthority) -> None:
    if not path.is_file() or path.is_symlink():
        raise ProvisionError(f"required regular file is absent or redirected: {path}")
    size = path.stat().st_size
    digest = _sha256(path)
    if size != authority.size or digest != authority.sha256:
        raise ProvisionError(
            f"file authority differs for {path}: "
            f"expected {authority.size}/{authority.sha256}, received {size}/{digest}"
        )


def _run_git(repository: Path, *arguments: str) -> None:
    result = subprocess.run(
        ("git", "-C", str(repository), *arguments),
        check=False,
        stdin=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise ProvisionError(f"git command failed with exit {result.returncode}: {arguments!r}")


def _checkout(repository: Path, url: str, revision: str, sparse_paths: tuple[str, ...]) -> None:
    repository.mkdir()
    _run_git(repository, "init", "--quiet")
    _run_git(repository, "config", "core.autocrlf", "false")
    _run_git(repository, "config", "advice.detachedHead", "false")
    _run_git(repository, "remote", "add", "origin", url)
    _run_git(repository, "sparse-checkout", "set", "--cone", *sparse_paths)
    _run_git(repository, "fetch", "--quiet", "--depth=1", "origin", revision)
    _run_git(repository, "checkout", "--quiet", "--detach", "FETCH_HEAD")
    received = subprocess.run(
        ("git", "-C", str(repository), "rev-parse", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if received != revision:
        raise ProvisionError(f"checkout revision differs: expected {revision}, received {received}")


def _copy_file(source_root: Path, destination_root: Path, relative: str) -> None:
    source = source_root.joinpath(*relative.split("/"))
    destination = destination_root.joinpath(*relative.split("/"))
    if not source.is_file() or source.is_symlink():
        raise ProvisionError(f"upstream file is absent or redirected: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def _copy_tree(source_root: Path, destination_root: Path, relative: str) -> None:
    source = source_root.joinpath(*relative.split("/"))
    destination = destination_root.joinpath(*relative.split("/"))
    if not source.is_dir() or source.is_symlink():
        raise ProvisionError(f"upstream tree is absent or redirected: {source}")
    shutil.copytree(source, destination, symlinks=True)


def _transport_asset(relative: str, authority: FileAuthority) -> Path:
    try:
        asset_root = runtime_asset_directory("msvc42-wine")
    except FileNotFoundError as error:
        raise ProvisionError(str(error)) from error
    source = asset_root / Path(relative).name
    _require_file(source, authority)
    return source


def _install_transport_assets(destination_root: Path) -> None:
    for relative, authority in _PROVISIONED_TRANSPORT_FILES.items():
        source = _transport_asset(relative, authority)
        destination = destination_root.joinpath(*relative.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            raise ProvisionError(f"transport destination already exists: {destination}")
        with source.open("rb") as input_stream, destination.open("xb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream)
        destination.chmod(0o755)
        _require_file(destination, authority)


def _patch_c2(path: Path) -> None:
    _require_file(path, _C2_UPSTREAM)
    payload = bytearray(path.read_bytes())
    for offset, expected, replacement in _C2_PATCHES:
        received = bytes(payload[offset : offset + len(expected)])
        if received != expected:
            raise ProvisionError(
                f"C2 patch preimage differs at 0x{offset:x}: "
                f"expected {expected.hex()}, received {received.hex()}"
            )
        payload[offset : offset + len(expected)] = replacement
    path.write_bytes(payload)
    _require_file(path, _FILES["bin/C2.EXE"])


def verify_msvc42(root: Path) -> None:
    requested_root = root.expanduser()
    if requested_root.is_symlink() or not requested_root.is_dir():
        raise ProvisionError(
            f"toolchain root is absent, not a directory, or redirected: {requested_root}"
        )
    admitted_root = requested_root.resolve(strict=True)
    for relative, file_authority in _FILES.items():
        _require_file(admitted_root.joinpath(*relative.split("/")), file_authority)
    for relative, file_authority in _PROVISIONED_TRANSPORT_FILES.items():
        _require_file(admitted_root.joinpath(*relative.split("/")), file_authority)
    for relative, tree_authority in _TREES.items():
        receipt = portable_tree_receipt(admitted_root.joinpath(*relative.split("/")), relative)
        received = TreeAuthority(
            receipt.entry_count,
            receipt.max_depth,
            receipt.membership_sha256,
            receipt.content_sha256,
        )
        if received != tree_authority:
            raise ProvisionError(
                f"portable tree authority differs for {relative}: "
                f"expected {tree_authority!r}, received {received!r}"
            )


def verify_msvc42_cmake_frontend(root: Path) -> None:
    """Authenticate the two NMake files used by CMake import."""

    requested_root = root.expanduser()
    if requested_root.is_symlink() or not requested_root.is_dir():
        raise ProvisionError(
            f"toolchain root is absent, not a directory, or redirected: {requested_root}"
        )
    admitted_root = requested_root.resolve(strict=True)
    for relative, authority in _CMAKE_FRONTEND_FILES.items():
        _require_file(
            admitted_root.joinpath(*relative.split("/")),
            authority,
        )


def provision_msvc42(
    destination: Path,
    progress: ProgressCallback | None = None,
) -> Path:
    requested_destination = destination.expanduser()
    if requested_destination.is_symlink():
        raise ProvisionError(
            f"toolchain destination must not be a redirected path: {requested_destination}"
        )
    destination = requested_destination.resolve(strict=False)
    if destination == Path(destination.anchor):
        raise ProvisionError("toolchain destination must not be a filesystem root")
    if destination.exists() or destination.is_symlink():
        _emit(progress, f"verifying existing destination {destination}")
        verify_msvc42(destination)
        _emit(progress, "existing toolchain is exact; no download needed")
        return destination

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".reprobit-msvc42-", dir=destination.parent)).resolve(
        strict=True
    )
    try:
        checkout_42 = temporary / "msvc420"
        checkout_50 = temporary / "msvc500"
        payload = temporary / "payload"
        payload.mkdir()

        _emit(progress, f"fetching msvc420@{MSVC420_REVISION[:12]}")
        _checkout(
            checkout_42,
            MSVC420_REPOSITORY,
            MSVC420_REVISION,
            ("bin", "include", "lib", "mfc/include", "mfc/lib"),
        )
        _emit(progress, f"fetching msvc500 redist@{MSVC500_REVISION[:12]}")
        _checkout(checkout_50, MSVC500_REPOSITORY, MSVC500_REVISION, ("redist",))

        for relative in (*_FILES, *_CMAKE_FRONTEND_FILES):
            if relative in {"bin/MSVCRT40.dll", "bin/msvcrt20.dll"}:
                continue
            _copy_file(checkout_42, payload, relative)
        for relative in _TREES:
            if relative in {"lib"}:
                continue
            _copy_tree(checkout_42, payload, relative)
        # lib was already created for MSVCRT.LIB; copy its remaining members.
        for source in (checkout_42 / "lib").iterdir():
            destination_file = payload / "lib" / source.name
            if not destination_file.exists():
                if not source.is_file() or source.is_symlink():
                    raise ProvisionError(f"4.2 library tree contains a redirected entry: {source}")
                shutil.copyfile(source, destination_file)
        _copy_file(checkout_50, payload, "redist/msvcrt40.dll")
        (payload / "redist" / "msvcrt40.dll").replace(payload / "bin" / "MSVCRT40.dll")
        _copy_file(checkout_50, payload, "redist/msvcrt20.dll")
        (payload / "redist" / "msvcrt20.dll").replace(payload / "bin" / "msvcrt20.dll")
        (payload / "redist").rmdir()

        _emit(progress, "installing authenticated cross-host transport files")
        _install_transport_assets(payload)

        _emit(progress, "applying the authenticated C2 patch")
        _patch_c2(payload / "bin" / "C2.EXE")
        _emit(progress, "authenticating files and portable input trees")
        verify_msvc42(payload)
        verify_msvc42_cmake_frontend(payload)
        payload.replace(destination)
        _emit(progress, f"published exact toolchain at {destination}")
        return destination
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


__all__ = [
    "MSVC420_REPOSITORY",
    "MSVC420_REVISION",
    "MSVC500_REPOSITORY",
    "MSVC500_REVISION",
    "ProgressCallback",
    "ProvisionError",
    "provision_msvc42",
    "verify_msvc42",
    "verify_msvc42_cmake_frontend",
]
