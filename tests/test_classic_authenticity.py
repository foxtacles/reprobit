from __future__ import annotations

import ast
import inspect
import subprocess
import sys
from pathlib import Path

import pytest

import reprobit.classic.composition as composition_algorithms
import reprobit.classic.foundation as foundation_algorithms
import reprobit.classic.ia32 as ia32_algorithms
import reprobit.classic.registers as register_algorithms
import reprobit.classic.relational as relational_algorithms
import reprobit.classic.rewriting as rewriting_algorithms
import reprobit.classic.scheduling as schedule_algorithms
from reprobit.binary import ByteIdentityError
from reprobit.legacy import LegacyOracleInstallGate

FORBIDDEN_PAYLOAD_PARAMETERS = {
    "oracle",
    "oracle_body",
    "oracle_bytes",
    "oracle_payload",
    "reference_body",
    "retail",
    "retail_body",
    "target_payload",
}
QUARANTINED_ORACLE_MODULE = "legacy_elision.py"
CANDIDATE_MODULES = (
    composition_algorithms,
    register_algorithms,
    relational_algorithms,
    rewriting_algorithms,
    schedule_algorithms,
)


def test_clean_candidate_entry_points_have_no_oracle_payload_parameter() -> None:
    producers = {
        f"{module.__name__}.{name}": value
        for module in CANDIDATE_MODULES
        for name, value in vars(module).items()
        if name.startswith("produce_")
        and inspect.isfunction(value)
        and value.__module__ == module.__name__
    }
    assert producers
    for name, producer in producers.items():
        parameters = set(inspect.signature(producer).parameters)
        assert not parameters.intersection(FORBIDDEN_PAYLOAD_PARAMETERS), name


def test_clean_primitive_rejects_an_oracle_keyword() -> None:
    with pytest.raises(TypeError):
        rewriting_algorithms.apply_simulated_region_rewrite(
            b"\xc3",
            [],
            frozenset(),
            "adversarial",
            retail_body=b"target",  # type: ignore[call-arg]
        )


def test_clean_primitive_rejects_a_nested_oracle_payload() -> None:
    with pytest.raises(ByteIdentityError, match="embedded payload"):
        rewriting_algorithms.apply_simulated_region_rewrite(
            b"\xc3",
            [{"oracle_payload": b"retail bytes"}],
            frozenset(),
            "adversarial",
        )


def test_clean_producer_rejects_bytes_hidden_under_an_ignored_key() -> None:
    with pytest.raises(ByteIdentityError, match="embeds a byte payload"):
        composition_algorithms.produce_reloc_divergent_candidate(
            b"not parsed",
            b"not parsed",
            {"notes": {"opaque": b"retail bytes"}},
        )


def test_source_refactor_candidate_authenticates_source_before_composition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[bytes, bytes, object, str]] = []

    def authenticate(
        seed_source: bytes,
        donor_source: bytes,
        proof: object,
        context: str,
    ) -> dict[str, object]:
        calls.append((seed_source, donor_source, proof, context))
        return {"source_authenticated": True}

    def compose(
        seed: bytes,
        donor: bytes,
        function: dict[str, object],
        **_: object,
    ) -> tuple[bytes, dict[str, object]]:
        assert seed == b"seed object"
        assert donor == b"donor object"
        assert function["target_source_refactor"] == {"kind": "closed"}
        return b"candidate", {"object_authenticated": True}

    monkeypatch.setattr(
        composition_algorithms,
        "require_target_source_refactor_identity",
        authenticate,
    )
    monkeypatch.setattr(composition_algorithms, "compose_same_slot_resize", compose)
    output, proof = composition_algorithms.produce_source_refactor_candidate(
        b"seed object",
        b"donor object",
        {
            "splice_class": "retail_exact_reloc_divergent",
            "target_source_refactor": {"kind": "closed"},
        },
        b"seed source",
        b"donor source",
    )
    assert output == b"candidate"
    assert proof == {
        "object_authenticated": True,
        "source_authenticated": True,
    }
    assert calls == [
        (
            b"seed source",
            b"donor source",
            {"kind": "closed"},
            "retail-exact source-refactor proof",
        )
    ]


def test_mosaic_declarations_reject_legacy_literal_instruction_fields() -> None:
    digest = "0" * 64
    declaration = [
        {
            "kind": "same_offset_complete_x86_instruction_v1",
            "start": 0,
            "end": 1,
            "seed_bytes": "90",
            "seed_sha256": digest,
            "donor_bytes": "c3",
            "donor_sha256": "1" * 64,
        }
    ]
    with pytest.raises(ByteIdentityError, match="schema differs"):
        ia32_algorithms.validate_instruction_mosaic_ranges(declaration, "adversarial", 1)


def test_mosaic_ranges_use_current_reprobit_donor_identifiers() -> None:
    declaration = [
        {
            "kind": "same_offset_complete_x86_instruction_v1",
            "start": 0,
            "end": 1,
            "seed_sha256": "0" * 64,
            "donor_sha256": "1" * 64,
            "donor": "donor_2611b2229ba41e75",
        }
    ]
    assert (
        ia32_algorithms.validate_instruction_mosaic_ranges(declaration, "mosaic", 1)[0]["donor"]
        == "donor_2611b2229ba41e75"
    )
    declaration[0]["donor"] = "Legacy Donor"
    with pytest.raises(ByteIdentityError, match="donor is invalid"):
        ia32_algorithms.validate_instruction_mosaic_ranges(declaration, "mosaic", 1)


def test_mosaic_trace_labels_use_the_explicit_primary_dependency() -> None:
    label = composition_algorithms._instruction_mosaic_range_donor_label
    assert label({}, "donor_primary") == "donor_primary"
    assert label({"donor": "donor_variant"}, "donor_primary") == "donor_variant"


def test_classic_package_has_no_oracle_capability_import_or_raw_body_api() -> None:
    package = Path(inspect.getfile(foundation_algorithms)).parent
    for path in package.glob("*.py"):
        if path.name == QUARANTINED_ORACLE_MODULE:
            continue
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parameters = {
                    argument.arg
                    for argument in (
                        *node.args.posonlyargs,
                        *node.args.args,
                        *node.args.kwonlyargs,
                    )
                }
                assert "retail_body" not in parameters
            if isinstance(node, ast.Subscript):
                key = node.slice
                assert not (isinstance(key, ast.Constant) and key.value == "retail_body")
        imported = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        assert "reprobit.verify" not in imported
        assert "reprobit.legacy" not in imported


def test_clean_canonical_imports_do_not_load_legacy_elision() -> None:
    script = """
import sys

import reprobit.classic.composition
import reprobit.classic_project

module = "reprobit.classic.legacy_elision"
if module in sys.modules:
    raise AssertionError(f"normal classic imports loaded quarantined module: {module}")
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_oracle_discovery_producer_was_removed() -> None:
    forbidden = {
        "restore_adjacent_thunk_pair_order",
        "compose_retail_exact_simulated_elision",
        "apply_replacements",
    }
    for module in CANDIDATE_MODULES:
        assert forbidden.isdisjoint(vars(module))
        assert not any("simulated_elision" in name for name in vars(module))


def test_direct_oracle_install_gate_lives_only_in_quarantine_module() -> None:
    assert LegacyOracleInstallGate.__module__ == "reprobit.legacy"
    assert all(not hasattr(module, "LegacyOracleInstallGate") for module in CANDIDATE_MODULES)
