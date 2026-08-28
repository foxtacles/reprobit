from __future__ import annotations

import ast
import inspect
import subprocess
import sys
from pathlib import Path

import pytest

from reprobit import classic
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


def test_clean_candidate_entry_points_have_no_oracle_payload_parameter() -> None:
    producers = {
        name: getattr(classic, name) for name in classic.__all__ if name.startswith("produce_")
    }
    assert producers
    for name, producer in producers.items():
        parameters = set(inspect.signature(producer).parameters)
        assert not parameters.intersection(FORBIDDEN_PAYLOAD_PARAMETERS), name


def test_clean_primitive_rejects_an_oracle_keyword() -> None:
    with pytest.raises(TypeError):
        classic.apply_simulated_region_rewrite(
            b"\xc3",
            [],
            frozenset(),
            "adversarial",
            retail_body=b"target",  # type: ignore[call-arg]
        )


def test_clean_primitive_rejects_a_nested_oracle_payload() -> None:
    with pytest.raises(classic.ByteIdentityError, match="embedded payload"):
        classic.apply_simulated_region_rewrite(
            b"\xc3",
            [{"oracle_payload": b"retail bytes"}],
            frozenset(),
            "adversarial",
        )


def test_clean_producer_rejects_bytes_hidden_under_an_ignored_key() -> None:
    with pytest.raises(classic.ByteIdentityError, match="embeds a byte payload"):
        classic.produce_reloc_divergent_candidate(
            b"not parsed",
            b"not parsed",
            {"notes": {"opaque": b"retail bytes"}},
        )


def test_source_refactor_candidate_authenticates_source_before_composition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from reprobit.classic import composition

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
        composition, "require_target_source_refactor_identity", authenticate
    )
    monkeypatch.setattr(composition, "compose_same_slot_resize", compose)
    output, proof = classic.produce_source_refactor_candidate(
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
    with pytest.raises(classic.ByteIdentityError, match="schema differs"):
        classic.validate_instruction_mosaic_ranges(declaration, "adversarial", 1)


def test_mosaic_trace_labels_a_migrated_primary_donor_without_legacy_identity() -> None:
    from reprobit.classic import composition

    label = composition._instruction_mosaic_range_donor_label
    primary = composition._instruction_mosaic_primary_donor_label
    assert primary({}) == "primary"
    assert primary({"donor": "legacy-primary"}) == "legacy-primary"
    assert primary(
        {
            "donor_variants": [{"donor": "variant"}],
            "instruction_ranges": [
                {"donor": "migrated-primary"},
                {"donor": "variant"},
            ],
        }
    ) == "migrated-primary"
    with pytest.raises(classic.ByteIdentityError, match="primary donor is ambiguous"):
        primary(
            {
                "instruction_ranges": [
                    {"donor": "first"},
                    {"donor": "second"},
                ]
            }
        )
    assert label({}, {}) == "primary"
    assert label({"donor": "legacy-primary"}, {}) == "legacy-primary"
    assert label({"donor": "legacy-primary"}, {"donor": "variant"}) == "variant"


def test_classic_package_has_no_oracle_capability_import_or_raw_body_api() -> None:
    package = Path(inspect.getfile(classic)).parent
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


def test_clean_classic_import_surface_does_not_load_legacy_elision() -> None:
    script = """
import sys

import reprobit.classic
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
    assert not hasattr(classic, "restore_adjacent_thunk_pair_order")
    assert not hasattr(classic, "compose_retail_exact_simulated_elision")
    assert not any("simulated_elision" in name for name in classic.__all__)
    assert "apply_replacements" not in classic.__all__
    assert not hasattr(classic, "apply_replacements")


def test_direct_oracle_install_gate_lives_only_in_quarantine_module() -> None:
    assert LegacyOracleInstallGate.__module__ == "reprobit.legacy"
    assert not hasattr(classic, "LegacyOracleInstallGate")
