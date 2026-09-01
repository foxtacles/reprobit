from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
SOURCE_ROOT = ROOT / "src"
PACKAGE_ROOT = SOURCE_ROOT / "reprobit"


def _module_name(path: Path) -> str:
    relative = path.relative_to(SOURCE_ROOT).with_suffix("")
    parts = relative.parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _internal_modules() -> dict[str, Path]:
    return {_module_name(path): path for path in PACKAGE_ROOT.rglob("*.py")}


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


def _dependencies(
    module: str,
    path: Path,
    modules: dict[str, Path],
) -> set[str]:
    dependencies: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
        if isinstance(node, ast.Import):
            candidates = tuple(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = _import_base(
                node,
                module=module,
                package_file=path.name == "__init__.py",
            )
            candidates = tuple(
                candidate
                for alias in node.names
                for candidate in (
                    f"{base}.{alias.name}" if alias.name != "*" else "",
                    base,
                )
            )
        else:
            continue
        for candidate in candidates:
            if candidate in modules and candidate != module:
                dependencies.add(candidate)
    return dependencies


def _module_scope_statements(tree: ast.Module) -> tuple[ast.stmt, ...]:
    pending = list(reversed(tree.body))
    statements: list[ast.stmt] = []
    while pending:
        statement = pending.pop()
        statements.append(statement)
        nested: list[ast.stmt] = []
        if isinstance(statement, ast.If | ast.For | ast.AsyncFor | ast.While):
            nested.extend(statement.body)
            nested.extend(statement.orelse)
        elif isinstance(statement, ast.With | ast.AsyncWith):
            nested.extend(statement.body)
        elif isinstance(statement, ast.Try):
            nested.extend(statement.body)
            nested.extend(statement.orelse)
            nested.extend(statement.finalbody)
            for handler in statement.handlers:
                nested.extend(handler.body)
        elif isinstance(statement, ast.Match):
            for case in statement.cases:
                nested.extend(case.body)
        pending.extend(reversed(nested))
    return tuple(statements)


def _assigned_names(target: ast.expr) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, ast.Tuple | ast.List):
        return {name for element in target.elts for name in _assigned_names(element)}
    if isinstance(target, ast.Starred):
        return _assigned_names(target.value)
    return set()


def _imported_only_bindings(tree: ast.Module) -> set[str]:
    imported: set[str] = set()
    owned: set[str] = set()
    for statement in _module_scope_statements(tree):
        if isinstance(statement, ast.Import):
            imported.update(
                alias.asname or alias.name.partition(".")[0] for alias in statement.names
            )
        elif isinstance(statement, ast.ImportFrom):
            imported.update(
                alias.asname or alias.name for alias in statement.names if alias.name != "*"
            )
        elif isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            owned.add(statement.name)
        elif isinstance(statement, ast.Assign):
            for target in statement.targets:
                owned.update(_assigned_names(target))
        elif isinstance(statement, ast.AnnAssign):
            owned.update(_assigned_names(statement.target))
    return imported - owned


def _mutates_all_dynamically(statement: ast.stmt) -> bool:
    targets: tuple[ast.AST, ...]
    if isinstance(statement, ast.Assign):
        targets = tuple(statement.targets)
    elif isinstance(statement, ast.AnnAssign | ast.AugAssign):
        targets = (statement.target,)
    elif isinstance(statement, ast.Delete | ast.Expr):
        targets = (statement,)
    else:
        return False
    return any(
        isinstance(node, ast.Name) and node.id == "__all__"
        for target in targets
        for node in ast.walk(target)
    )


def _literal_all(tree: ast.Module, path: Path) -> tuple[str, ...] | None:
    declarations: list[ast.expr] = []
    for statement in _module_scope_statements(tree):
        if (
            isinstance(statement, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "__all__"
                for target in statement.targets
            )
        ) or (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == "__all__"
            and statement.value is not None
        ):
            if statement.value is not None:
                declarations.append(statement.value)
        elif _mutates_all_dynamically(statement):
            raise AssertionError(f"dynamic __all__ in {path.relative_to(ROOT)}")
    if not declarations:
        return None
    if len(declarations) != 1:
        raise AssertionError(f"multiple __all__ declarations in {path.relative_to(ROOT)}")
    try:
        value = ast.literal_eval(declarations[0])
    except (TypeError, ValueError) as exc:
        raise AssertionError(f"non-literal __all__ in {path.relative_to(ROOT)}") from exc
    if not isinstance(value, list | tuple) or any(not isinstance(item, str) for item in value):
        raise AssertionError(f"invalid __all__ in {path.relative_to(ROOT)}")
    return tuple(value)


def test_internal_module_import_graph_is_acyclic() -> None:
    modules = _internal_modules()
    graph = {module: _dependencies(module, path, modules) for module, path in modules.items()}
    visited: set[str] = set()
    active: list[str] = []
    active_set: set[str] = set()

    def visit(module: str) -> None:
        if module in visited:
            return
        if module in active_set:
            start = active.index(module)
            cycle = " -> ".join((*active[start:], module))
            raise AssertionError(f"internal import cycle: {cycle}")
        active.append(module)
        active_set.add(module)
        for dependency in sorted(graph[module]):
            visit(dependency)
        active.pop()
        active_set.remove(module)
        visited.add(module)

    for module in sorted(graph):
        visit(module)


def test_classic_package_is_documentation_only() -> None:
    path = PACKAGE_ROOT / "classic" / "__init__.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    assert len(tree.body) == 1
    expression = tree.body[0]
    assert isinstance(expression, ast.Expr)
    assert isinstance(expression.value, ast.Constant)
    assert isinstance(expression.value.value, str)


def test_production_imports_and_exports_internal_owners_directly() -> None:
    modules = _internal_modules()
    trees = {
        module: ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for module, path in modules.items()
    }
    borrowed = {module: _imported_only_bindings(tree) for module, tree in trees.items()}
    allowed_borrowed_exports = {("reprobit", "Verdict")}
    violations: list[str] = []
    for module, path in modules.items():
        tree = trees[module]
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            base = _import_base(
                node,
                module=module,
                package_file=path.name == "__init__.py",
            )
            if base not in modules:
                continue
            for alias in node.names:
                location = f"{path.relative_to(ROOT)}:{node.lineno}"
                if alias.name == "*":
                    violations.append(f"{location}: star import from {base}")
                    continue
                child = f"{base}.{alias.name}"
                if child in modules:
                    violations.append(f"{location}: import module {child} directly")
                elif (
                    alias.name in borrowed[base]
                    and (base, alias.name) not in allowed_borrowed_exports
                ):
                    violations.append(f"{location}: {base}.{alias.name} is owned by another module")

        declared_all = _literal_all(tree, path)
        for name in declared_all or ():
            if name in borrowed[module] and (module, name) not in allowed_borrowed_exports:
                violations.append(f"{path.relative_to(ROOT)}: __all__ borrows {module}.{name}")
    assert not violations, (
        f"import and export names from their defining internal modules: {violations}"
    )


# Module prefixes that build on the classic package: the classic runtime,
# project and repair layer, execution and state, the CLI and every workflow
# above it.  The package may reach the model, format, path and toolchain-profile
# foundations, never these.
CLASSIC_UPPER_LAYERS = (
    "reprobit.classic_",
    "reprobit.backends",
    "reprobit.cache",
    "reprobit.cli",
    "reprobit.cmake",
    "reprobit.discovery",
    "reprobit.engine",
    "reprobit.evidence_audit",
    "reprobit.execution",
    "reprobit.incremental",
    "reprobit.msvc",
    "reprobit.repair",
    "reprobit.report",
    "reprobit.scheduler",
    "reprobit.state",
    "reprobit.transactions",
    "reprobit.verify",
)


def test_classic_package_is_a_leaf_beneath_the_runtime_layers() -> None:
    modules = _internal_modules()
    graph = {module: _dependencies(module, path, modules) for module, path in modules.items()}
    roots = sorted(module for module in modules if module.startswith("reprobit.classic."))
    assert roots
    parent: dict[str, str | None] = dict.fromkeys(roots)
    pending = list(roots)
    while pending:
        module = pending.pop()
        for dependency in sorted(graph[module]):
            if dependency not in parent:
                parent[dependency] = module
                pending.append(dependency)
    violations: list[str] = []
    for module in sorted(parent):
        if not module.startswith(CLASSIC_UPPER_LAYERS):
            continue
        chain = [module]
        while (owner := parent[chain[-1]]) is not None:
            chain.append(owner)
        violations.append(" -> ".join(reversed(chain)))
    assert not violations, f"the classic package imports a layer built on it: {violations}"
