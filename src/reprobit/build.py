"""Canonical, shell-free build plans and link admissions."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


class BuildPlanError(ValueError):
    """Raised when a build plan is ambiguous, unsafe, or inconsistent."""


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:+/-]*$")


def _check_text(value: str, label: str) -> None:
    if not value:
        raise BuildPlanError(f"{label} cannot be empty")
    if "\0" in value or "\n" in value or "\r" in value:
        raise BuildPlanError(f"{label} contains a forbidden control character")


@dataclass(frozen=True, slots=True)
class BuildStep:
    """One argv-based process invocation.

    ``environment`` is the complete declared addition for this step.  An
    executor decides which separately declared baseline variables are present;
    the step never requests inheritance of the ambient process environment.
    """

    id: str
    argv: tuple[str, ...]
    cwd: str
    depends_on: tuple[str, ...] = ()
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    timeout_seconds: float = 600.0

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.id):
            raise BuildPlanError(f"invalid build-step id: {self.id!r}")
        if not self.argv:
            raise BuildPlanError(f"build step {self.id!r} has an empty argv")
        for index, argument in enumerate(self.argv):
            _check_text(argument, f"argv[{index}] for {self.id!r}")
        _check_text(self.cwd, f"cwd for {self.id!r}")
        if self.timeout_seconds <= 0:
            raise BuildPlanError(f"timeout for {self.id!r} must be positive")
        if len(set(self.depends_on)) != len(self.depends_on):
            raise BuildPlanError(f"build step {self.id!r} has duplicate dependencies")
        if self.id in self.depends_on:
            raise BuildPlanError(f"build step {self.id!r} depends on itself")
        if len(set(self.inputs)) != len(self.inputs):
            raise BuildPlanError(f"build step {self.id!r} has duplicate inputs")
        if len(set(self.outputs)) != len(self.outputs):
            raise BuildPlanError(f"build step {self.id!r} has duplicate outputs")
        keys = [key for key, _ in self.environment]
        if len(set(keys)) != len(keys):
            raise BuildPlanError(f"build step {self.id!r} has duplicate environment keys")
        if keys != sorted(keys):
            raise BuildPlanError(f"build step {self.id!r} environment must be key-sorted")
        for key, value in self.environment:
            _check_text(key, f"environment key for {self.id!r}")
            if "=" in key:
                raise BuildPlanError(f"environment key for {self.id!r} contains '='")
            if "\0" in value:
                raise BuildPlanError(f"environment value for {self.id!r} contains NUL")


@dataclass(frozen=True, slots=True)
class LinkAdmission:
    """A typed request to admit one produced object at a precise link seat."""

    id: str
    target: str
    artifact_id: str
    object_path: str
    insertion_index: int | None = None
    before: str | None = None
    after: str | None = None
    expected_symbol: str | None = None

    def __post_init__(self) -> None:
        for label, value in (
            ("link-admission id", self.id),
            ("link target", self.target),
            ("artifact id", self.artifact_id),
            ("object path", self.object_path),
        ):
            _check_text(value, label)
        selectors = sum(
            value is not None for value in (self.insertion_index, self.before, self.after)
        )
        if selectors > 1:
            raise BuildPlanError(
                f"link admission {self.id!r} may select only one of index, before, or after"
            )
        if self.insertion_index is not None and self.insertion_index < 0:
            raise BuildPlanError("link insertion index cannot be negative")


@dataclass(frozen=True, slots=True)
class BuildPlan:
    """Canonical build DAG exchanged between project adapters and executors."""

    steps: tuple[BuildStep, ...]
    link_admissions: tuple[LinkAdmission, ...] = ()
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise BuildPlanError(f"unsupported build-plan schema {self.schema_version}")
        step_index = {step.id: step for step in self.steps}
        if len(step_index) != len(self.steps):
            raise BuildPlanError("build-step ids must be unique")
        for step in self.steps:
            missing = set(step.depends_on).difference(step_index)
            if missing:
                raise BuildPlanError(
                    f"build step {step.id!r} has missing dependencies: {sorted(missing)!r}"
                )
        output_owners: dict[str, str] = {}
        for step in self.steps:
            for output in step.outputs:
                if owner := output_owners.get(output):
                    raise BuildPlanError(
                        f"output {output!r} is produced by both {owner!r} and {step.id!r}"
                    )
                output_owners[output] = step.id
        if len({admission.id for admission in self.link_admissions}) != len(self.link_admissions):
            raise BuildPlanError("link-admission ids must be unique")
        self._validate_acyclic(step_index)

    def _validate_acyclic(self, steps: Mapping[str, BuildStep]) -> None:
        visiting: set[str] = set()
        complete: set[str] = set()

        def visit(step_id: str, trail: tuple[str, ...]) -> None:
            if step_id in complete:
                return
            if step_id in visiting:
                raise BuildPlanError(f"build-plan cycle: {' -> '.join((*trail, step_id))}")
            visiting.add(step_id)
            for dependency in steps[step_id].depends_on:
                visit(dependency, (*trail, step_id))
            visiting.remove(step_id)
            complete.add(step_id)

        for step_id in steps:
            visit(step_id, ())

    def ordered_steps(self) -> tuple[BuildStep, ...]:
        """Return a stable dependency-first topological order."""

        by_id = {step.id: step for step in self.steps}
        result: list[BuildStep] = []
        seen: set[str] = set()

        def add(step_id: str) -> None:
            if step_id in seen:
                return
            step = by_id[step_id]
            for dependency in step.depends_on:
                add(dependency)
            seen.add(step_id)
            result.append(step)

        for step in self.steps:
            add(step.id)
        return tuple(result)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "steps": [
                {
                    "id": step.id,
                    "argv": list(step.argv),
                    "cwd": step.cwd,
                    "depends_on": list(step.depends_on),
                    "inputs": list(step.inputs),
                    "outputs": list(step.outputs),
                    "environment": {key: value for key, value in step.environment},
                    "timeout_seconds": step.timeout_seconds,
                }
                for step in self.steps
            ],
            "link_admissions": [
                {
                    "id": admission.id,
                    "target": admission.target,
                    "artifact_id": admission.artifact_id,
                    "object_path": admission.object_path,
                    "insertion_index": admission.insertion_index,
                    "before": admission.before,
                    "after": admission.after,
                    "expected_symbol": admission.expected_symbol,
                }
                for admission in self.link_admissions
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")) + "\n"

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> BuildPlan:
        _require_keys(value, {"schema_version", "steps", "link_admissions"}, "build plan")
        raw_steps = _sequence(value.get("steps"), "build-plan steps")
        steps: list[BuildStep] = []
        for raw in raw_steps:
            if not isinstance(raw, Mapping):
                raise BuildPlanError("every build-plan step must be an object")
            _require_keys(
                raw,
                {
                    "id",
                    "argv",
                    "cwd",
                    "depends_on",
                    "inputs",
                    "outputs",
                    "environment",
                    "timeout_seconds",
                },
                "build step",
            )
            environment = raw.get("environment", {})
            if not isinstance(environment, Mapping) or not all(
                isinstance(key, str) and isinstance(item, str) for key, item in environment.items()
            ):
                raise BuildPlanError("build-step environment must map strings to strings")
            steps.append(
                BuildStep(
                    id=_string(raw.get("id"), "build-step id"),
                    argv=_strings(raw.get("argv"), "build-step argv"),
                    cwd=_string(raw.get("cwd"), "build-step cwd"),
                    depends_on=_strings(raw.get("depends_on", []), "build-step dependencies"),
                    inputs=_strings(raw.get("inputs", []), "build-step inputs"),
                    outputs=_strings(raw.get("outputs", []), "build-step outputs"),
                    environment=tuple(sorted(environment.items())),
                    timeout_seconds=_number(raw.get("timeout_seconds", 600), "build-step timeout"),
                )
            )
        admissions: list[LinkAdmission] = []
        for raw in _sequence(value.get("link_admissions", []), "link admissions"):
            if not isinstance(raw, Mapping):
                raise BuildPlanError("every link admission must be an object")
            _require_keys(
                raw,
                {
                    "id",
                    "target",
                    "artifact_id",
                    "object_path",
                    "insertion_index",
                    "before",
                    "after",
                    "expected_symbol",
                },
                "link admission",
            )
            admissions.append(
                LinkAdmission(
                    id=_string(raw.get("id"), "link-admission id"),
                    target=_string(raw.get("target"), "link target"),
                    artifact_id=_string(raw.get("artifact_id"), "artifact id"),
                    object_path=_string(raw.get("object_path"), "object path"),
                    insertion_index=_optional_int(raw.get("insertion_index"), "insertion index"),
                    before=_optional_string(raw.get("before"), "before selector"),
                    after=_optional_string(raw.get("after"), "after selector"),
                    expected_symbol=_optional_string(raw.get("expected_symbol"), "expected symbol"),
                )
            )
        schema_version = value.get("schema_version")
        if type(schema_version) is not int:
            raise BuildPlanError("build-plan schema_version must be an integer")
        return cls(tuple(steps), tuple(admissions), schema_version)

    @classmethod
    def from_json(cls, value: str) -> BuildPlan:
        try:
            parsed = json.loads(value, object_pairs_hook=_reject_duplicate_pairs)
        except json.JSONDecodeError as error:
            raise BuildPlanError(f"invalid build-plan JSON: {error}") from error
        if not isinstance(parsed, Mapping):
            raise BuildPlanError("a build plan must be a JSON object")
        return cls.from_dict(parsed)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BuildPlanError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _require_keys(value: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(value).difference(allowed)
    if unknown:
        raise BuildPlanError(f"unknown {label} fields: {sorted(unknown)!r}")


def _sequence(value: Any, label: str) -> Sequence[Any]:
    if not isinstance(value, list):
        raise BuildPlanError(f"{label} must be an array")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise BuildPlanError(f"{label} must be a string")
    return value


def _optional_string(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _string(value, label)


def _strings(value: Any, label: str) -> tuple[str, ...]:
    sequence = _sequence(value, label)
    if not all(isinstance(item, str) for item in sequence):
        raise BuildPlanError(f"every value in {label} must be a string")
    return tuple(sequence)


def _number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BuildPlanError(f"{label} must be a number")
    return float(value)


def _optional_int(value: Any, label: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int:
        raise BuildPlanError(f"{label} must be an integer")
    return value
