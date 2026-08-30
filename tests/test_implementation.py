from __future__ import annotations

import shutil
from collections.abc import Sequence
from pathlib import Path

import pytest

import reprobit.classic.semantic_contracts as semantic_contracts
import reprobit.implementation as implementation
import reprobit.incremental as incremental
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest
from reprobit.secure_path_contracts import SecureFileSnapshot
from reprobit.secure_paths import read_relative_file

ROOT = Path(__file__).parents[1]
PACKAGE_ROOT = ROOT / "src" / "reprobit"
CLASSIC_ROOT_MODULES = (
    "reprobit.classic.semantic_contracts",
    "reprobit.classic_runtime_preparation",
)
PRODUCER_ROOT_MODULES = ("reprobit.classic_incremental",)
GRAPH_CLI_ROOT_MODULES = ("reprobit.cli_graph",)


def _copy_package(tmp_path: Path) -> Path:
    destination = tmp_path / "reprobit"
    shutil.copytree(
        PACKAGE_ROOT,
        destination,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    return destination


def _minimal_package(tmp_path: Path, entry: str) -> Path:
    package = tmp_path / "reprobit"
    package.mkdir()
    (package / "__init__.py").write_text('"""Test package."""\n', encoding="utf-8")
    (package / "entry.py").write_text(entry, encoding="utf-8")
    return package


def _relative_closure(package: Path, roots: Sequence[str]) -> tuple[str, ...]:
    return tuple(
        path.relative_to(package).as_posix()
        for path in implementation._package_import_closure_paths(package, roots)
    )


def test_classic_implementation_import_closure_has_exact_architecture_boundary() -> None:
    relative = _relative_closure(PACKAGE_ROOT, CLASSIC_ROOT_MODULES)

    assert relative == tuple(sorted(set(relative)))
    assert {
        "__init__.py",
        "classic/__init__.py",
        "classic/semantic_contracts.py",
        "classic/source_overlay_claims.py",
        "classic_evidence.py",
        "classic_execution_records.py",
        "classic_publication.py",
        "classic_runtime.py",
        "classic_runtime_probe.py",
        "classic_runtime_donor.py",
        "classic_runtime_environment.py",
        "classic_runtime_files.py",
        "classic_runtime_graph.py",
        "classic_runtime_overlay.py",
        "classic_runtime_preparation.py",
        "classic_runtime_producer.py",
        "classic_runtime_receipts.py",
        "classic_runtime_warm.py",
        "implementation.py",
    }.issubset(relative)
    assert {
        "classic_incremental.py",
        "cli.py",
        "discovery.py",
    }.isdisjoint(relative)
    assert not any(
        path.startswith(
            (
                "classic_incremental",
                "cmake_configure",
                "cli",
                "discovery",
                "incremental",
            )
        )
        for path in relative
    )
    assert (
        implementation.scoped_package_import_closure_digest(CLASSIC_ROOT_MODULES)
    ) == semantic_contracts.CLASSIC_VALIDATOR_IMPLEMENTATION_DIGEST


def test_classic_validator_revalidation_rejects_a_changed_closure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        semantic_contracts,
        "_classic_implementation_digest",
        lambda: Digest.from_bytes(b"changed classic validator closure"),
    )

    with pytest.raises(ClassicSemanticError, match="validator implementation changed"):
        semantic_contracts.revalidate_classic_validator_implementation()


def test_graph_cli_import_closure_has_a_narrow_boundary() -> None:
    relative = _relative_closure(PACKAGE_ROOT, GRAPH_CLI_ROOT_MODULES)

    assert "cli_graph.py" in relative
    assert "project_loader.py" in relative
    assert {"cli.py", "discovery.py", "classic_incremental.py"}.isdisjoint(relative)


def test_incremental_producer_import_closure_has_a_narrow_product_boundary() -> None:
    relative = _relative_closure(PACKAGE_ROOT, PRODUCER_ROOT_MODULES)

    assert relative == tuple(sorted(set(relative)))
    assert {
        "cache.py",
        "classic_incremental.py",
        "classic_incremental_execution.py",
        "classic_incremental_planning.py",
        "classic_execution_records.py",
        "classic_runtime.py",
        "classic_runtime_files.py",
        "classic_runtime_producer.py",
        "classic_runtime_receipts.py",
        "incremental.py",
        "incremental_executor.py",
    }.issubset(relative)
    assert {
        "cli.py",
        "cli_output.py",
        "discovery.py",
        "discovery_cli.py",
        "discovery_report_html.py",
        "progress.py",
        "report_html.py",
        "report_html_style.py",
    }.isdisjoint(relative)
    assert not any(
        path.startswith(("cli", "discovery", "progress", "report_html")) for path in relative
    )
    assert incremental.producer_implementation_digest() == (
        implementation.scoped_package_import_closure_digest(PRODUCER_ROOT_MODULES)
    )


@pytest.mark.parametrize(
    "relative",
    (
        "cli.py",
        "cli_output.py",
        "discovery_report_html.py",
        "progress.py",
        "report_html.py",
        "report_html_style.py",
    ),
)
def test_incremental_producer_digest_excludes_non_output_product_surfaces(
    tmp_path: Path,
    relative: str,
) -> None:
    package = _copy_package(tmp_path)
    baseline = implementation._scoped_package_import_closure_digest(
        package,
        PRODUCER_ROOT_MODULES,
    )

    path = package / relative
    path.write_bytes(path.read_bytes() + b"\n# excluded producer digest perturbation\n")

    assert (
        implementation._scoped_package_import_closure_digest(
            package,
            PRODUCER_ROOT_MODULES,
        )
        == baseline
    )


@pytest.mark.parametrize(
    "relative",
    (
        "classic_incremental.py",
        "classic_execution_records.py",
        "classic_runtime_files.py",
        "classic_runtime_producer.py",
        "classic_runtime_receipts.py",
        "incremental_executor.py",
    ),
)
def test_incremental_producer_digest_binds_output_affecting_runtime_seams(
    tmp_path: Path,
    relative: str,
) -> None:
    package = _copy_package(tmp_path)
    baseline = implementation._scoped_package_import_closure_digest(
        package,
        PRODUCER_ROOT_MODULES,
    )

    path = package / relative
    path.write_bytes(path.read_bytes() + b"\n# included producer digest perturbation\n")

    assert (
        implementation._scoped_package_import_closure_digest(
            package,
            PRODUCER_ROOT_MODULES,
        )
        != baseline
    )


def test_incremental_producer_revalidation_rejects_a_changed_closure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = incremental.producer_implementation_digest()
    monkeypatch.setattr(
        incremental,
        "producer_implementation_digest",
        lambda: Digest.from_bytes(b"changed incremental producer closure"),
    )

    with pytest.raises(RuntimeError, match="implementation changed"):
        incremental.revalidate_producer_implementation(expected)


@pytest.mark.parametrize(
    "relative",
    (
        "classic/source_overlay_claims.py",
        "classic_runtime_producer.py",
        "classic_runtime_files.py",
        "classic_runtime_receipts.py",
        "classic_execution_records.py",
        "classic_evidence.py",
        "classic_publication.py",
    ),
)
def test_classic_validator_digest_binds_each_proof_execution_and_publication_seam(
    tmp_path: Path,
    relative: str,
) -> None:
    package = _copy_package(tmp_path)
    baseline = implementation._scoped_package_import_closure_digest(
        package,
        CLASSIC_ROOT_MODULES,
    )
    baseline_validator = semantic_contracts._source_overlay_validator_digest(baseline)

    path = package / relative
    path.write_bytes(path.read_bytes() + b"\n# implementation digest perturbation\n")
    changed = implementation._scoped_package_import_closure_digest(
        package,
        CLASSIC_ROOT_MODULES,
    )

    assert changed != baseline
    assert semantic_contracts._source_overlay_validator_digest(changed) != baseline_validator
    assert semantic_contracts.SOURCE_OVERLAY_VALIDATOR_ID == ("classic.source-overlay-ancestry.v1")


@pytest.mark.parametrize(
    "relative",
    ("classic_incremental.py", "cli.py", "discovery.py"),
)
def test_classic_validator_digest_excludes_unrelated_product_surfaces(
    tmp_path: Path,
    relative: str,
) -> None:
    package = _copy_package(tmp_path)
    baseline = implementation._scoped_package_import_closure_digest(
        package,
        CLASSIC_ROOT_MODULES,
    )

    path = package / relative
    path.write_bytes(path.read_bytes() + b"\n# excluded digest perturbation\n")

    assert (
        implementation._scoped_package_import_closure_digest(
            package,
            CLASSIC_ROOT_MODULES,
        )
        == baseline
    )


@pytest.mark.parametrize(
    "roots",
    (
        (),
        tuple(reversed(CLASSIC_ROOT_MODULES)),
        (*CLASSIC_ROOT_MODULES, CLASSIC_ROOT_MODULES[-1]),
        ("reprobit.not-valid!",),
    ),
)
def test_import_closure_requires_canonical_root_order(roots: tuple[str, ...]) -> None:
    with pytest.raises(RuntimeError, match="roots must be non-empty and canonical"):
        implementation._package_import_closure_paths(PACKAGE_ROOT, roots)


def test_import_closure_visits_nested_and_conditional_runtime_imports_only(
    tmp_path: Path,
) -> None:
    package = _minimal_package(
        tmp_path,
        """from typing import TYPE_CHECKING
import typing

if TYPE_CHECKING:
    import reprobit.type_only

if typing.TYPE_CHECKING:
    import reprobit.qualified_type_checking

if FLAG:
    import reprobit.left
else:
    import reprobit.right

def load() -> None:
    import reprobit.nested
""",
    )
    for name in (
        "left.py",
        "nested.py",
        "qualified_type_checking.py",
        "right.py",
        "type_only.py",
    ):
        (package / name).write_text("", encoding="utf-8")

    relative = _relative_closure(package, ("reprobit.entry",))

    assert relative == (
        "__init__.py",
        "entry.py",
        "left.py",
        "nested.py",
        "qualified_type_checking.py",
        "right.py",
    )


@pytest.mark.parametrize(
    "dynamic_source",
    (
        '__import__("reprobit.hidden")\n',
        'import importlib\nimportlib.import_module("reprobit.hidden")\n',
        'from importlib import import_module as load\nload("reprobit.hidden")\n',
    ),
)
def test_import_closure_refuses_dynamic_imports(
    tmp_path: Path,
    dynamic_source: str,
) -> None:
    package = _minimal_package(tmp_path, dynamic_source)
    (package / "hidden.py").write_text("", encoding="utf-8")

    with pytest.raises(RuntimeError, match="refuses dynamic imports"):
        implementation._package_import_closure_paths(package, ("reprobit.entry",))


def test_import_closure_refuses_missing_internal_modules(tmp_path: Path) -> None:
    package = _minimal_package(tmp_path, "import reprobit.missing\n")

    with pytest.raises(RuntimeError, match="references an absent module"):
        implementation._package_import_closure_paths(package, ("reprobit.entry",))


def test_import_closure_refuses_missing_roots(tmp_path: Path) -> None:
    package = _minimal_package(tmp_path, "")

    with pytest.raises(RuntimeError, match="root is absent"):
        implementation._package_import_closure_paths(
            package,
            ("reprobit.missing",),
        )


def test_import_closure_refuses_missing_package_ancestors(tmp_path: Path) -> None:
    package = _minimal_package(tmp_path, "")
    child = package / "child"
    child.mkdir()
    (child / "entry.py").write_text("", encoding="utf-8")

    with pytest.raises(RuntimeError, match="lacks package ancestor"):
        implementation._package_import_closure_paths(
            package,
            ("reprobit.child.entry",),
        )


def test_import_closure_refuses_redirected_python_modules(tmp_path: Path) -> None:
    package = _minimal_package(tmp_path, "import reprobit.redirected\n")
    target = tmp_path / "redirected.py"
    target.write_text("", encoding="utf-8")
    try:
        (package / "redirected.py").symlink_to(target)
    except OSError as exc:
        pytest.skip(f"host cannot create test symlinks: {exc}")

    with pytest.raises(RuntimeError, match="absent or redirected"):
        implementation._package_import_closure_paths(package, ("reprobit.entry",))


def test_import_closure_refuses_nonregular_python_modules(tmp_path: Path) -> None:
    package = _minimal_package(tmp_path, "")
    (package / "not_regular.py").mkdir()

    with pytest.raises(RuntimeError, match="absent or redirected"):
        implementation._package_import_closure_paths(package, ("reprobit.entry",))


def test_import_closure_refuses_ambiguous_module_entries(tmp_path: Path) -> None:
    package = _minimal_package(tmp_path, "")
    (package / "seat.py").write_text("", encoding="utf-8")
    seat = package / "seat"
    seat.mkdir()
    (seat / "__init__.py").write_text("", encoding="utf-8")

    with pytest.raises(RuntimeError, match="ambiguous module entries"):
        implementation._package_import_closure_paths(package, ("reprobit.entry",))


def test_import_closure_refuses_case_colliding_modules(tmp_path: Path) -> None:
    package = _minimal_package(tmp_path, "")
    (package / "Seat.py").write_text("", encoding="utf-8")
    seat = package / "seat"
    seat.mkdir()
    (seat / "__init__.py").write_text("", encoding="utf-8")

    with pytest.raises(RuntimeError, match="case-colliding modules"):
        implementation._package_import_closure_paths(package, ("reprobit.entry",))


def test_import_closure_ignores_external_package_name_prefixes(tmp_path: Path) -> None:
    package = _minimal_package(tmp_path, "import reprobit_external.helper\n")

    assert _relative_closure(package, ("reprobit.entry",)) == (
        "__init__.py",
        "entry.py",
    )


def test_import_closure_hashes_the_same_snapshot_it_parses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = _minimal_package(tmp_path, "")
    baseline = implementation._scoped_package_import_closure_digest(
        package,
        ("reprobit.entry",),
    )
    real_read = read_relative_file

    def mutate_after_read(
        root: Path,
        relative: str,
    ) -> tuple[bytes, SecureFileSnapshot]:
        payload, snapshot = real_read(root, relative)
        if relative == "entry.py":
            (root / relative).write_bytes(payload + b"# changed after snapshot\n")
        return payload, snapshot

    monkeypatch.setattr(implementation, "read_relative_file", mutate_after_read)

    captured = implementation._scoped_package_import_closure_digest(
        package,
        ("reprobit.entry",),
    )

    assert captured == baseline
    assert (package / "entry.py").read_bytes() == b"# changed after snapshot\n"


def test_resolved_import_closure_rehash_does_not_repeat_static_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = _minimal_package(tmp_path, "import reprobit.dependency\n")
    dependency = package / "dependency.py"
    dependency.write_text("VALUE = 1\n", encoding="utf-8")
    roots = ("reprobit.entry",)
    baseline, paths = implementation._scoped_package_import_closure_receipt(
        package,
        roots,
    )
    monkeypatch.setattr(
        implementation,
        "_package_import_closure_entries",
        lambda *_args, **_kwargs: pytest.fail("resolved closure was parsed again"),
    )

    assert implementation._rehash_scoped_package_import_closure(package, roots, paths) == baseline

    dependency.write_text("VALUE = 2\n", encoding="utf-8")
    assert implementation._rehash_scoped_package_import_closure(package, roots, paths) != baseline
