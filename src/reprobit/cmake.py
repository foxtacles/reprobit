"""CMake import target-plan reader and packaged module lookup."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reprobit.build import BuildPlanError, LinkAdmission


@dataclass(frozen=True, slots=True)
class CMakeTargetRecord:
    name: str
    artifact_id: str
    output: str
    pdb: str | None = None


@dataclass(frozen=True, slots=True)
class CMakeExportPlan:
    """Target metadata emitted by ``ReproBit.cmake`` at generate time."""

    targets: tuple[CMakeTargetRecord, ...]
    link_admissions: tuple[LinkAdmission, ...] = ()
    schema_version: int = 1

    @classmethod
    def from_json(cls, raw: str) -> CMakeExportPlan:
        try:
            value = json.loads(raw, object_pairs_hook=_no_duplicates)
        except json.JSONDecodeError as error:
            raise BuildPlanError(f"invalid CMake export-plan JSON: {error}") from error
        if not isinstance(value, Mapping):
            raise BuildPlanError("CMake export plan must be a JSON object")
        unknown = set(value).difference({"schema_version", "targets", "link_admissions"})
        if unknown:
            raise BuildPlanError(f"unknown CMake export-plan fields: {sorted(unknown)!r}")
        if value.get("schema_version") != 1:
            raise BuildPlanError("unsupported CMake export-plan schema")
        raw_targets = value.get("targets")
        if not isinstance(raw_targets, list):
            raise BuildPlanError("CMake export-plan targets must be an array")
        targets: list[CMakeTargetRecord] = []
        for raw_target in raw_targets:
            if not isinstance(raw_target, Mapping):
                raise BuildPlanError("CMake target record must be an object")
            extra = set(raw_target).difference({"name", "artifact_id", "output", "pdb"})
            if extra:
                raise BuildPlanError(f"unknown CMake target fields: {sorted(extra)!r}")
            targets.append(
                CMakeTargetRecord(
                    name=_required_string(raw_target, "name"),
                    artifact_id=_required_string(raw_target, "artifact_id"),
                    output=_required_string(raw_target, "output"),
                    pdb=_optional_string(raw_target, "pdb"),
                )
            )
        raw_admissions = value.get("link_admissions", [])
        if not isinstance(raw_admissions, list):
            raise BuildPlanError("CMake link admissions must be an array")
        admissions: list[LinkAdmission] = []
        for raw_admission in raw_admissions:
            if not isinstance(raw_admission, Mapping):
                raise BuildPlanError("CMake link admission must be an object")
            extra = set(raw_admission).difference(
                {
                    "id",
                    "target",
                    "artifact_id",
                    "object_path",
                    "insertion_index",
                    "before",
                    "after",
                    "expected_symbol",
                }
            )
            if extra:
                raise BuildPlanError(f"unknown CMake admission fields: {sorted(extra)!r}")
            index = raw_admission.get("insertion_index")
            if index is not None and type(index) is not int:
                raise BuildPlanError("CMake admission insertion_index must be an integer")
            admissions.append(
                LinkAdmission(
                    id=_required_string(raw_admission, "id"),
                    target=_required_string(raw_admission, "target"),
                    artifact_id=_required_string(raw_admission, "artifact_id"),
                    object_path=_required_string(raw_admission, "object_path"),
                    insertion_index=index,
                    before=_optional_string(raw_admission, "before"),
                    after=_optional_string(raw_admission, "after"),
                    expected_symbol=_optional_string(raw_admission, "expected_symbol"),
                )
            )
        if len({target.name for target in targets}) != len(targets):
            raise BuildPlanError("CMake target records must have unique names")
        return cls(tuple(targets), tuple(admissions))

    @classmethod
    def read(cls, path: Path) -> CMakeExportPlan:
        return cls.from_json(path.read_text(encoding="utf-8"))


def cmake_module_path() -> Path:
    """Return the installed directory containing ``ReproBit.cmake``."""

    package_directory = Path(__file__).resolve().parent
    repository_root = package_directory.parents[1]
    source_tree = repository_root / "cmake"
    if (repository_root / "pyproject.toml").is_file() and (
        source_tree / "ReproBit.cmake"
    ).is_file():
        return source_tree
    installed = package_directory.parent / "share" / "reprobit" / "cmake"
    if (installed / "ReproBit.cmake").is_file():
        return installed
    raise FileNotFoundError("the packaged ReproBit.cmake module is missing")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BuildPlanError(f"duplicate JSON key: {key!r}")
        value[key] = item
    return value


def _required_string(value: Mapping[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise BuildPlanError(f"CMake field {key!r} must be a non-empty string")
    return item


def _optional_string(value: Mapping[str, Any], key: str) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    if not isinstance(item, str) or not item:
        raise BuildPlanError(f"CMake field {key!r} must be a non-empty string or null")
    return item
