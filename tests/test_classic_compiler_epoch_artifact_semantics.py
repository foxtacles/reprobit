"""The closed artifact-semantics decision of the project-overlay compiler audit."""

from __future__ import annotations

import pytest

from reprobit.classic.compiler_epoch import _artifact_semantics_decision

_TRACE_THEOREM = "closed-source-compiler-congruence-coff-envelope-v1"
_DIGESTS = {"counterfactual_digest": {"a": 1}, "effective_digest": {"b": 2}}


def _decide(**overrides: object):
    arguments: dict[str, object] = {
        "projection_required": True,
        "projection_equal": False,
        "projection_byte_equal": False,
        "projection_theorem": None,
        "projection_proof": None,
        "compiler_state_projection": None,
        "coff_trace": {"theorem": _TRACE_THEOREM, "changed_code_section_count": 0},
        **_DIGESTS,
    }
    arguments.update(overrides)
    return _artifact_semantics_decision(**arguments)  # type: ignore[arg-type]


def test_identical_retained_code_cites_the_envelope_congruence() -> None:
    decision = _decide()
    assert decision.proven
    assert decision.runtime_projection_theorem == _TRACE_THEOREM
    assert decision.artifact_semantics_theorem == _TRACE_THEOREM
    assert decision.runtime_projection_proof == {
        "theorem": _TRACE_THEOREM,
        "changed_code_section_count": 0,
        "counterfactual_object": {"a": 1},
        "effective_object": {"b": 2},
    }


@pytest.mark.parametrize(
    "trace",
    [
        {"theorem": _TRACE_THEOREM, "changed_code_section_count": 1},
        {"theorem": _TRACE_THEOREM, "changed_code_section_count": "0"},
        {"theorem": _TRACE_THEOREM, "changed_code_section_count": False},
        {"theorem": _TRACE_THEOREM},
        {"changed_code_section_count": 0},
    ],
)
def test_a_code_delta_or_malformed_trace_still_needs_a_delta_theorem(trace: dict) -> None:
    decision = _decide(coff_trace=trace)
    assert not decision.proven
    assert decision.runtime_projection_theorem is None
    assert decision.artifact_semantics_theorem is None


def test_compiler_state_theorem_takes_precedence_over_identity() -> None:
    projection = {"theorem": "msvc-4.20-compiler-state-code-image-v1", "sections": []}
    decision = _decide(compiler_state_projection=projection)
    assert decision.proven
    assert decision.runtime_projection_theorem == "msvc-4.20-compiler-state-code-image-v1"
    assert decision.runtime_projection_proof == projection


def test_runtime_projection_theorem_takes_precedence_over_everything() -> None:
    proof = {"theorem": "alpha"}
    decision = _decide(projection_equal=True, projection_theorem="alpha", projection_proof=proof)
    assert decision.proven
    assert decision.runtime_projection_theorem == "alpha"
    assert decision.runtime_projection_proof == proof


def test_byte_equal_objects_cite_exact_projection_before_identity() -> None:
    decision = _decide(projection_equal=True, projection_byte_equal=True)
    assert decision.proven
    assert decision.runtime_projection_theorem == "exact-runtime-projection-v1"


def test_unrequired_projection_cites_the_trace_theorem_and_is_proven() -> None:
    decision = _decide(
        projection_required=False,
        coff_trace={"theorem": _TRACE_THEOREM, "changed_code_section_count": 3},
    )
    assert decision.proven
    assert decision.runtime_projection_theorem is None
    assert decision.artifact_semantics_theorem == _TRACE_THEOREM
