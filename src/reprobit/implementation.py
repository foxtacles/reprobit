"""Content identity for the installed ReproBit implementation."""

from __future__ import annotations

import ast
import heapq
from collections.abc import Sequence
from functools import cache
from pathlib import Path, PurePosixPath

from reprobit.assets import runtime_asset_path
from reprobit.model import Digest
from reprobit.secure_path_contracts import (
    SecureFileSnapshot,
    SecurePathError,
)
from reprobit.secure_paths import (
    digest_relative_file,
    read_relative_file,
)
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


def scoped_package_implementation_digest(relative_paths: Sequence[str]) -> Digest:
    """Hash one explicit, canonical closure of shipped package files."""

    paths = tuple(relative_paths)
    if not paths or paths != tuple(sorted(set(paths))):
        raise RuntimeError("ReproBit implementation scope must be non-empty and canonical")
    package_root = Path(__file__).resolve(strict=True).parent
    material: list[dict[str, object]] = []
    for relative in paths:
        logical = PurePosixPath(relative)
        if (
            not relative
            or logical.is_absolute()
            or logical.as_posix() != relative
            or any(part in {"", ".", ".."} for part in logical.parts)
        ):
            raise RuntimeError(f"invalid ReproBit implementation scope path: {relative!r}")
        path = package_root.joinpath(*logical.parts)
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(
                f"ReproBit implementation scope input is absent or redirected: {relative}"
            )
        material.append(_identity_bound_material(package_root, path, role=relative))
    return Digest.from_bytes(
        canonical_json(
            {
                "schema_version": 1,
                "files": material,
            }
        )
    )


def _canonical_root_modules(root_modules: Sequence[str]) -> tuple[str, ...]:
    roots = tuple(root_modules)
    if not roots or any(
        not isinstance(root, str)
        or not root
        or any(not part.isidentifier() for part in root.split("."))
        for root in roots
    ):
        raise RuntimeError("ReproBit import-closure roots must be non-empty and canonical")
    if roots != tuple(sorted(set(roots))):
        raise RuntimeError("ReproBit import-closure roots must be non-empty and canonical")
    return roots


def _package_module_paths(package_root: Path) -> dict[str, Path]:
    if package_root.is_symlink() or not package_root.is_dir():
        raise RuntimeError("ReproBit import-closure package root is absent or redirected")
    entries = tuple(package_root.rglob("*"))
    package = package_root.name
    modules: dict[str, Path] = {}
    folded_modules: dict[str, str] = {}
    python_entries = tuple(
        sorted(
            (path for path in entries if path.suffix == ".py"),
            key=lambda item: item.relative_to(package_root).as_posix(),
        )
    )
    for path in python_entries:
        if path.is_symlink() or not path.is_file():
            relative_path = path.relative_to(package_root).as_posix()
            raise RuntimeError(
                f"ReproBit import-closure module is absent or redirected: {relative_path}"
            )
        relative_module = path.relative_to(package_root).with_suffix("")
        parts = relative_module.parts
        if parts[-1] == "__init__":
            parts = parts[:-1]
        module = ".".join((package, *parts))
        prior_path = modules.get(module)
        if prior_path is not None:
            raise RuntimeError(
                "ReproBit import closure has ambiguous module entries: "
                f"{prior_path.relative_to(package_root).as_posix()}, "
                f"{path.relative_to(package_root).as_posix()}"
            )
        folded = module.casefold()
        prior_module = folded_modules.get(folded)
        if prior_module is not None and prior_module != module:
            raise RuntimeError(
                f"ReproBit import closure has case-colliding modules: {prior_module}, {module}"
            )
        modules[module] = path
        folded_modules[folded] = module
    return modules


def _import_base(
    node: ast.ImportFrom,
    *,
    module: str,
    package_file: bool,
) -> str:
    if not node.level:
        return node.module or ""
    package = module if package_file else module.rpartition(".")[0]
    parts = package.split(".") if package else []
    retained = len(parts) - node.level + 1
    if retained < 0:
        return ""
    prefix = ".".join(parts[:retained])
    return ".".join(part for part in (prefix, node.module or "") if part)


def _is_type_checking_guard(node: ast.expr) -> bool:
    return isinstance(node, ast.Name) and node.id == "TYPE_CHECKING"


class _StaticImportCollector(ast.NodeVisitor):
    """Collect runtime-reachable imports without executing package code."""

    def __init__(self) -> None:
        self.imports: list[ast.Import | ast.ImportFrom] = []
        self.loaded_names: list[ast.Name] = []
        self.loaded_attributes: list[ast.Attribute] = []

    def visit_If(self, node: ast.If) -> None:
        if _is_type_checking_guard(node.test):
            for statement in node.orelse:
                self.visit(statement)
            return
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        self.imports.append(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.imports.append(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            self.loaded_names.append(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, ast.Load):
            self.loaded_attributes.append(node)
        self.generic_visit(node)


def _static_internal_dependencies(
    module: str,
    path: Path,
    payload: bytes,
    modules: dict[str, Path],
    *,
    package: str,
) -> tuple[str, ...]:
    tree = ast.parse(payload, filename=str(path))
    collector = _StaticImportCollector()
    collector.visit(tree)

    importlib_aliases = {"importlib"}
    import_module_aliases: set[str] = set()
    for node in collector.imports:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib":
                    importlib_aliases.add(alias.asname or "importlib")
        elif node.level == 0 and node.module == "importlib":
            for alias in node.names:
                if alias.name == "import_module":
                    import_module_aliases.add(alias.asname or alias.name)
    dynamic_line: int | None = None
    for loaded_name in collector.loaded_names:
        if loaded_name.id == "__import__" or loaded_name.id in import_module_aliases:
            dynamic_line = loaded_name.lineno
            break
    if dynamic_line is None:
        for loaded_attribute in collector.loaded_attributes:
            if (
                loaded_attribute.attr == "import_module"
                and isinstance(loaded_attribute.value, ast.Name)
                and loaded_attribute.value.id in importlib_aliases
            ):
                dynamic_line = loaded_attribute.lineno
                break
    if dynamic_line is not None:
        raise RuntimeError(
            f"ReproBit import closure refuses dynamic imports: {module}:{dynamic_line}"
        )

    dependencies: set[str] = set()
    for node in collector.imports:
        if isinstance(node, ast.Import):
            for alias in node.names:
                candidate = alias.name
                if candidate in modules:
                    dependencies.add(candidate)
                elif candidate == package or candidate.startswith(f"{package}."):
                    raise RuntimeError(
                        "ReproBit import closure references an absent module: "
                        f"{module} -> {candidate}"
                    )
            continue

        base = _import_base(
            node,
            module=module,
            package_file=path.name == "__init__.py",
        )
        if node.level and not (base == package or base.startswith(f"{package}.")):
            raise RuntimeError(f"ReproBit import closure has an invalid relative import: {module}")
        if base in modules:
            dependencies.add(base)
        elif base == package or base.startswith(f"{package}."):
            raise RuntimeError(
                f"ReproBit import closure references an absent module: {module} -> {base}"
            )
        for alias in node.names:
            if alias.name == "*":
                continue
            candidate = ".".join(part for part in (base, alias.name) if part)
            if candidate in modules:
                dependencies.add(candidate)
    return tuple(sorted(dependencies))


def _package_import_closure_entries(
    package_root: Path,
    root_modules: Sequence[str],
) -> tuple[tuple[Path, bytes, SecureFileSnapshot], ...]:
    """Resolve one deterministic, static package-local import closure."""

    roots = _canonical_root_modules(root_modules)
    modules = _package_module_paths(package_root)
    package = package_root.name
    for root in roots:
        if root not in modules:
            raise RuntimeError(f"ReproBit import-closure root is absent: {root}")
        if root != package and not root.startswith(f"{package}."):
            raise RuntimeError(f"ReproBit import-closure root is outside {package}: {root}")

    pending = list(roots)
    heapq.heapify(pending)
    visited: set[str] = set()
    snapshots: dict[str, tuple[bytes, SecureFileSnapshot]] = {}
    while pending:
        module = heapq.heappop(pending)
        if module in visited:
            continue
        path = modules[module]
        visited.add(module)
        relative_path = path.relative_to(package_root).as_posix()
        try:
            payload, snapshot = read_relative_file(package_root, relative_path)
        except SecurePathError as exc:
            raise RuntimeError(
                f"ReproBit import-closure module is unstable: {relative_path}"
            ) from exc
        snapshots[module] = (payload, snapshot)

        parts = module.split(".")
        for width in range(1, len(parts)):
            ancestor = ".".join(parts[:width])
            ancestor_path = modules.get(ancestor)
            if ancestor_path is None or ancestor_path.name != "__init__.py":
                raise RuntimeError(f"ReproBit import closure lacks package ancestor: {ancestor}")
            if ancestor not in visited:
                heapq.heappush(pending, ancestor)

        for dependency in _static_internal_dependencies(
            module,
            path,
            payload,
            modules,
            package=package,
        ):
            if dependency not in visited:
                heapq.heappush(pending, dependency)

    return tuple(
        sorted(
            ((modules[module], snapshots[module][0], snapshots[module][1]) for module in visited),
            key=lambda item: item[0].relative_to(package_root).as_posix(),
        )
    )


def _package_import_closure_paths(
    package_root: Path,
    root_modules: Sequence[str],
) -> tuple[Path, ...]:
    return tuple(
        path
        for path, _payload, _snapshot in _package_import_closure_entries(
            package_root,
            root_modules,
        )
    )


def _scoped_package_import_closure_digest(
    package_root: Path,
    root_modules: Sequence[str],
) -> Digest:
    roots = _canonical_root_modules(root_modules)
    entries = _package_import_closure_entries(package_root, roots)
    material = [
        {
            "path": path.relative_to(package_root).as_posix(),
            "digest": snapshot.digest,
            "size": snapshot.size,
        }
        for path, _payload, snapshot in entries
    ]
    return Digest.from_bytes(
        canonical_json(
            {
                "schema_version": 1,
                "root_modules": list(roots),
                "files": material,
            }
        )
    )


def scoped_package_import_closure_digest(root_modules: Sequence[str]) -> Digest:
    """Hash the static package-local import closure of canonical module roots."""

    package_root = Path(__file__).resolve(strict=True).parent
    return _scoped_package_import_closure_digest(package_root, root_modules)


@cache
def package_implementation_digest() -> Digest:
    """Hash every shipped implementation file and executed runtime asset."""

    return _compute_package_implementation_digest()


def revalidate_package_implementation(expected: Digest) -> None:
    """Fail if editable implementation bytes changed during one invocation."""

    actual = _compute_package_implementation_digest()
    if actual != expected:
        raise RuntimeError(
            "ReproBit package implementation changed during execution; rerun the build"
        )


__all__ = [
    "package_implementation_digest",
    "revalidate_package_implementation",
    "scoped_package_implementation_digest",
    "scoped_package_import_closure_digest",
]
