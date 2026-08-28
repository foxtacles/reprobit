"""Content identity for the installed ReproBit implementation."""

from __future__ import annotations

from functools import cache
from pathlib import Path

from reprobit.assets import runtime_asset_path
from reprobit.model import Digest
from reprobit.secure_paths import SecurePathError, digest_relative_file
from reprobit.strict_json import canonical_json


def _identity_bound_material(root: Path, path: Path, *, role: str) -> dict[str, object]:
    try:
        relative = path.relative_to(root).as_posix()
        snapshot = digest_relative_file(root, relative)
    except (SecurePathError, ValueError) as exc:
        raise RuntimeError(f"ReproBit implementation input is unstable: {role}") from exc
    return {
        "path": role,
        "digest": snapshot.digest,
        "size": snapshot.size,
    }


def _compute_package_implementation_digest() -> Digest:
    package_root = Path(__file__).resolve(strict=True).parent
    entries = tuple(path for path in package_root.rglob("*") if "__pycache__" not in path.parts)
    symlinks = tuple(path for path in entries if path.is_symlink())
    if symlinks:
        rendered = ", ".join(path.relative_to(package_root).as_posix() for path in symlinks)
        raise RuntimeError(f"ReproBit package identity refuses symlink entries: {rendered}")
    files = tuple(
        sorted(
            (path for path in entries if path.is_file() and path.suffix not in {".pyc", ".pyo"}),
            key=lambda item: item.relative_to(package_root).as_posix(),
        )
    )
    material = [
        _identity_bound_material(
            package_root,
            path,
            role=path.relative_to(package_root).as_posix(),
        )
        for path in files
    ]
    proxy = runtime_asset_path("ReproBitPathProxy.sh")
    if proxy.is_symlink() or not proxy.is_file():
        raise RuntimeError("ReproBit runtime path-proxy asset is absent or redirected")
    material.append(
        _identity_bound_material(
            proxy.parent,
            proxy,
            # A stable role, not an installation-specific source/wheel path.
            role="@runtime/path-proxy-template",
        )
    )
    return Digest.from_bytes(canonical_json(material))


@cache
def package_implementation_digest() -> Digest:
    """Hash every shipped implementation file and executed runtime asset."""

    return _compute_package_implementation_digest()


def revalidate_package_implementation(expected: Digest) -> None:
    """Fail if editable implementation bytes changed during one invocation."""

    actual = _compute_package_implementation_digest()
    if actual != expected:
        raise RuntimeError(
            "ReproBit package implementation changed during warm execution; rerun the build"
        )


__all__ = ["package_implementation_digest", "revalidate_package_implementation"]
