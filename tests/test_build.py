from __future__ import annotations

import pytest

from reprobit.build import (
    BuildPlan,
    BuildPlanError,
    BuildStep,
    LinkAdmission,
)


def _plan() -> BuildPlan:
    return BuildPlan(
        (
            BuildStep(
                "compile",
                ("cc", "-c", "unit.c"),
                "R:/src",
                inputs=("R:/src/unit.c",),
                outputs=("R:/build/unit.obj",),
                environment=(("LANG", "C"),),
            ),
            BuildStep(
                "link",
                ("link", "unit.obj"),
                "R:/build",
                depends_on=("compile",),
                inputs=("R:/build/unit.obj",),
                outputs=("R:/build/app.exe",),
            ),
        ),
        (
            LinkAdmission(
                "admit.unit",
                "app",
                "unit.object",
                "R:/build/unit.obj",
                before="library.lib",
                expected_symbol="_entry",
            ),
        ),
    )


def test_plan_round_trip_is_canonical_and_keeps_complete_admission() -> None:
    plan = _plan()
    encoded = plan.to_json()
    decoded = BuildPlan.from_json(encoded)

    assert decoded == plan
    assert decoded.to_json() == encoded
    admission = decoded.link_admissions[0]
    assert admission.before == "library.lib"
    assert admission.expected_symbol == "_entry"
    assert admission.object_path == "R:/build/unit.obj"
    assert [step.id for step in decoded.ordered_steps()] == ["compile", "link"]


def test_plan_rejects_cycles_duplicate_outputs_and_unknown_json_fields() -> None:
    with pytest.raises(BuildPlanError, match="cycle"):
        BuildPlan(
            (
                BuildStep("a", ("tool",), ".", depends_on=("b",)),
                BuildStep("b", ("tool",), ".", depends_on=("a",)),
            )
        )
    with pytest.raises(BuildPlanError, match="produced by both"):
        BuildPlan(
            (
                BuildStep("a", ("tool",), ".", outputs=("out",)),
                BuildStep("b", ("tool",), ".", outputs=("out",)),
            )
        )
    raw = _plan().to_json().replace('"schema_version":1', '"extra":1,"schema_version":1')
    with pytest.raises(BuildPlanError, match="unknown build plan fields"):
        BuildPlan.from_json(raw)


def test_plan_rejects_duplicate_json_keys() -> None:
    with pytest.raises(BuildPlanError, match="duplicate JSON key"):
        BuildPlan.from_json(
            '{"schema_version":1,"schema_version":1,"steps":[],"link_admissions":[]}'
        )


def test_build_step_rejects_shell_control_characters() -> None:
    with pytest.raises(BuildPlanError, match="control character"):
        BuildStep("bad", ("tool\nnext",), ".")


def test_deep_build_plan_validates_and_orders_without_recursion() -> None:
    count = 2000
    steps = tuple(
        BuildStep(
            str(index),
            ("tool",),
            ".",
            depends_on=(str(index - 1),) if index else (),
        )
        for index in reversed(range(count))
    )
    plan = BuildPlan(steps)
    assert tuple(step.id for step in plan.ordered_steps()) == tuple(map(str, range(count)))


def test_build_plan_preserves_input_and_dependency_order() -> None:
    plan = BuildPlan(
        (
            BuildStep("link", ("tool",), ".", depends_on=("z", "a")),
            BuildStep("a", ("tool",), ".", depends_on=("shared",)),
            BuildStep("z", ("tool",), ".", depends_on=("shared",)),
            BuildStep("shared", ("tool",), "."),
            BuildStep("independent", ("tool",), "."),
        )
    )
    assert tuple(step.id for step in plan.ordered_steps()) == (
        "shared",
        "z",
        "a",
        "link",
        "independent",
    )


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), float("-inf")])
def test_build_plan_rejects_nonfinite_timeouts(timeout: float) -> None:
    with pytest.raises(BuildPlanError, match="finite and positive"):
        BuildStep("bad", ("tool",), ".", timeout_seconds=timeout)
