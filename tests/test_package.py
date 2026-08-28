from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

import reprobit
from reprobit.assets import runtime_asset_path
from reprobit.report import report_json_schema
from reprobit.schema import project_document_schemas
from reprobit.strict_json import canonical_json

ROOT = Path(__file__).parents[1]


def test_version_is_exposed() -> None:
    assert reprobit.__version__


def test_committed_json_schemas_are_current() -> None:
    expected = {
        **{
            name: canonical_json(schema)
            for name, schema in project_document_schemas().items()
        },
        "report-v2.schema.json": canonical_json(report_json_schema()),
    }
    assert {path.name for path in (ROOT / "schemas").glob("*.schema.json")} == set(
        expected
    )
    for name, generated in expected.items():
        assert (ROOT / "schemas" / name).read_bytes() == generated


def test_wheel_declares_required_non_python_assets() -> None:
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert configuration["project"]["version"] == reprobit.__version__
    assert configuration["project"]["license"] == "LGPL-3.0-only"
    assert configuration["project"]["license-files"] == ["LICENSE", "NOTICE"]
    included = configuration["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    assert included == {
        "cmake": "share/reprobit/cmake",
        "runtime": "share/reprobit/runtime",
        "schemas": "share/reprobit/schemas",
    }
    for relative in (
        "LICENSE",
        "NOTICE",
        "cmake/ReproBit.cmake",
        "runtime/ReproBitPathProxy.sh",
        "src/reprobit/py.typed",
    ):
        assert (ROOT / relative).is_file()
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert '"share/reprobit/runtime/ReproBitPathProxy.sh"' in workflow
    assert '"share/reprobit/cmake/ReproBitPathProxy.sh"' not in workflow


@pytest.mark.parametrize(
    "name",
    ("../LICENSE", r"..\LICENSE", "a/b", r"a\b", "C:LICENSE", ""),
)
def test_runtime_asset_lookup_rejects_non_component_names(name: str) -> None:
    with pytest.raises(ValueError, match="one safe path component"):
        runtime_asset_path(name)


def test_classic_core_has_no_blanket_static_analysis_suppressions() -> None:
    for path in (ROOT / "src/reprobit/classic").glob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "# ruff: noqa" not in source
        assert "# mypy: ignore-errors" not in source
