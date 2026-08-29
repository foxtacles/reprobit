from __future__ import annotations

import json
import tomllib
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from reprobit.costs import CostModel, calculate_cost
from reprobit.migration import (
    MigrationError,
    MigrationOutput,
    convert_v2_manifest,
    load_legacy_manifest,
    migration_output,
)
from reprobit.project_loader import load_project_tree
from reprobit.schema import ClassicRecipeFamily
from reprobit.toolchains import MSVC_42, TOOLCHAIN_PROFILES


def _manifest() -> dict[str, Any]:
    return {
        "schema": 2,
        "phase": "example",
        "toolchain": {
            "compiler_sha256": "3" * 64,
            "codegen_path_contract": {
                "source_root": "/workspace/sample",
                "build_root": "/workspace/sample-build",
                "compiler": "/opt/compiler/wine/x86/cl",
            },
            "backend_profiles": {
                "fixture": {
                    "compiler_support_files": [
                        {
                            "path": "wine/x86/cl",
                            "sha256": "3" * 64,
                            "roles": ["compiler"],
                        },
                        {
                            "path": "bin/msvcrt20.dll",
                            "sha256": "3" * 64,
                            "roles": ["runtime"],
                        },
                        {
                            "path": "bin/RCDLL.DLL",
                            "sha256": "3" * 64,
                            "roles": ["runtime"],
                        },
                    ],
                    "sealed_include_trees": [
                        {
                            "path": "wine/include",
                            "entry_count": 1,
                            "max_depth": 1,
                            "membership_sha256": "4" * 64,
                            "content_sha256": "5" * 64,
                        }
                    ],
                }
            },
        },
        "execution_backends": {
            "profiles": [
                {
                    "toolchain_commit": "6" * 40,
                    "toolchain_files": {
                        Path(path).name: "3" * 64
                        for path in (
                            *TOOLCHAIN_PROFILES[MSVC_42].required_producers,
                            "bin/MSVCRT40.dll",
                        )
                    },
                }
            ]
        },
        "target_policies": [],
        "translation_units": [
            {
                "target": "sample",
                "source": "src/sample.cpp",
                "source_sha256": "0" * 64,
                "source_size": 0,
                "mode": "compose",
                "donors": [
                    {
                        "id": "donor_a",
                        "status": "fresh",
                        "authenticity": "compiler",
                        "recipe": {
                            "kind": "donor_source_overlay",
                            "expected_size": 12,
                        },
                    }
                ],
                "functions": [
                    {
                        "mangled": "?sample@@YAXXZ",
                        "donor": "donor_a",
                        "splice_class": "equal_body_strict",
                        "expected_body_length": 12,
                    }
                ],
            }
        ],
        "archives": [],
        "images": {
            "SAMPLE": {
                "target": "sample",
                "original": "oracles/sample.exe",
                "original_sha256": "1" * 64,
                "original_size": 12,
                "recompiled": "sample.exe",
            }
        },
        "terminal_producers": {
            "link": {"tools": [], "project_sdk_libraries": [], "library_trees": []}
        },
        "source_overlay": {
            "schema": 1,
            "outputs": [],
            "graph": {"generated_tus": [], "link_admissions": []},
        },
    }


def _tu_path(result: MigrationOutput, section: str) -> PurePosixPath:
    return next(path for path in result.files if str(path).startswith(f"reprobit/{section}/tus/"))


def test_convert_v2_manifest_splits_intent_and_expected_pins() -> None:
    manifest = _manifest()
    manifest["toolchain"].update(
        {
            "python_sha256": "9" * 64,
            "python_version": "host-specific diagnostic",
            "max_child_seconds": 240,
        }
    )
    result = convert_v2_manifest(manifest, "2" * 64)
    assert PurePosixPath("reprobit.toml") in result.files
    assert result.intervention_count == 2
    build_plan = json.loads(result.files[PurePosixPath("reprobit/build-plan.json")])
    assert build_plan["toolchain_policy"] == {"max_child_seconds": 240}
    shard = json.loads(result.files[_tu_path(result, "interventions")])
    function = next(item for item in shard["interventions"] if item["role"] == "function")
    assert all(item["name"] != "expected_body_length" for item in function["parameters"])

    proof = json.loads(result.files[_tu_path(result, "proofs")])
    receipt = next(
        item for item in proof["expected_observations"] if item["intervention_id"] == function["id"]
    )
    assert receipt["expected_values"] == {"expected_body_length": 12}
    assert receipt["redactions"] == []

    project = tomllib.loads(result.files[PurePosixPath("reprobit.toml")].decode())
    assert project["project_id"] == "sample"
    assert project["paths"] == {
        "id": "migrated-pinned-v1",
        "source": r"Z:\workspace\sample-build\src",
        "build": r"Z:\workspace\sample-build\build",
        "toolchain": r"Z:\opt\compiler",
    }
    toolchain_lock = json.loads(result.files[PurePosixPath("reprobit/toolchain.lock.json")])
    sources = {source["repository"]: source for source in toolchain_lock["profile_sources"]}
    assert sources["https://github.com/archaic-msvc/msvc420.git"]["revision"] == (
        "b42c244f0a83ba15ba2ffb62b0dc240d7b2dea50"
    )
    assert sources["https://github.com/archaic-msvc/msvc500.git"]["revision"] == (
        "8abf95ce980161ad87b0b02402269cce76988953"
    )
    assert "bin/RCDLL.DLL" in sources["https://github.com/archaic-msvc/msvc420.git"]["paths"]
    assert set(sources["https://github.com/archaic-msvc/msvc500.git"]["paths"]) == {
        "bin/MSVCRT40.dll",
        "bin/msvcrt20.dll",
    }
    assert "source_revision" not in toolchain_lock


def test_convert_v2_manifest_accepts_a_leading_digit_cmake_target() -> None:
    manifest = _manifest()
    manifest["translation_units"][0]["target"] = "3dmanager"

    result = convert_v2_manifest(manifest, "2" * 64)

    build_plan = json.loads(result.files[PurePosixPath("reprobit/build-plan.json")])
    assert build_plan["translation_units"][0]["build_target"] == "3dmanager"
    intervention = json.loads(result.files[_tu_path(result, "interventions")])
    assert intervention["build_target"] == "3dmanager"
    assert {item["build_target"] for item in intervention["interventions"]} == {"3dmanager"}


def test_migration_partitions_source_overlay_semantic_claims_with_their_operations(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    manifest["source_overlay"] = {
        "schema": 2,
        "outputs": [
            {
                "path": "sample/unit.cpp",
                "clean": "0" * 64,
                "clean_size": 0,
                "effective": "1" * 64,
                "size": 1,
                "ops": [
                    {
                        "id": "op_sample_claim",
                        "op": "insert",
                        "anchor": {"at": "start", "b": 0, "ctx": "2" * 64},
                        "gen": {"k": "empty_scopes", "scope_count": 1},
                    }
                ],
            }
        ],
        "graph": {"generated_tus": [], "link_admissions": []},
    }
    claims = {
        "schema": 1,
        "bindings": [
            {
                "kind": "function_scope",
                "operation": "op_sample_claim",
                "leaf": 0,
                "function": "sample",
                "range_sha256": "3" * 64,
                "range_size": 1,
                "bindings": [],
            }
        ],
    }
    claims_path = tmp_path / "claims.json"
    claims_path.write_text(json.dumps(claims), encoding="utf-8")

    result = convert_v2_manifest(
        manifest,
        "2" * 64,
        semantic_claims_path=claims_path,
    )
    shared = json.loads(result.files[PurePosixPath("reprobit/interventions/shared-sample.json")])
    overlay = next(
        item for item in shared["interventions"] if item["family"] == "source_overlay_graph"
    )
    fields = {item["name"]: item["value"] for item in overlay["parameters"]}

    assert fields["semantic_claims"] == claims


def test_migration_rejects_a_semantic_claim_for_an_unknown_overlay_operation(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    claims_path = tmp_path / "claims.json"
    claims_path.write_text(
        json.dumps(
            {
                "schema": 1,
                "bindings": [
                    {
                        "kind": "logical_header",
                        "operation": "op_missing",
                        "leaf": 0,
                        "logical_path": "sample/header.h",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(MigrationError, match="unknown operation"):
        convert_v2_manifest(
            manifest,
            "2" * 64,
            semantic_claims_path=claims_path,
        )


def test_migration_rejects_claims_embedded_in_the_historical_manifest() -> None:
    manifest = _manifest()
    manifest["source_overlay"]["semantic_claims"] = {"schema": 1, "bindings": []}

    with pytest.raises(MigrationError, match=r"must remain immutable.*--semantic-claims"):
        convert_v2_manifest(manifest, "2" * 64)


def test_migration_rejects_a_non_closed_semantic_claims_sidecar(tmp_path: Path) -> None:
    claims_path = tmp_path / "claims.json"
    claims_path.write_text(
        json.dumps({"schema": 1, "bindings": [], "unreviewed": True}),
        encoding="utf-8",
    )

    with pytest.raises(MigrationError, match="must be exactly"):
        convert_v2_manifest(
            _manifest(),
            "2" * 64,
            semantic_claims_path=claims_path,
        )


def test_migration_requires_explicit_claims_for_ambiguous_overlay_generators() -> None:
    manifest = _manifest()
    manifest["source_overlay"] = {
        "schema": 2,
        "outputs": [
            {
                "path": "sample/unit.cpp",
                "clean": "0" * 64,
                "clean_size": 0,
                "effective": "1" * 64,
                "size": 1,
                "ops": [
                    {
                        "id": "op_sample_claim",
                        "op": "insert",
                        "anchor": {"at": "start", "b": 0, "ctx": "2" * 64},
                        "gen": {"k": "empty_scopes", "scope_count": 1},
                    }
                ],
            }
        ],
        "graph": {"generated_tus": [], "link_admissions": []},
    }

    with pytest.raises(
        MigrationError,
        match=r"requires an explicit semantic-claims sidecar.*op_sample_claim\[0\]"
        r"=function_scope",
    ):
        convert_v2_manifest(manifest, "2" * 64)


def test_migration_emits_empty_claims_when_no_generator_requires_one() -> None:
    manifest = _manifest()
    manifest["source_overlay"] = {
        "schema": 2,
        "outputs": [
            {
                "path": "sample/unit.cpp",
                "clean": "0" * 64,
                "clean_size": 0,
                "effective": "1" * 64,
                "size": 1,
                "ops": [
                    {
                        "id": "op_size_assert",
                        "op": "insert",
                        "anchor": {"at": "start", "b": 0, "ctx": "2" * 64},
                        "gen": {
                            "k": "size_asserts",
                            "assertions": [{"size": 4, "type": "Sample"}],
                            "at": [1],
                            "lines": 2,
                        },
                    }
                ],
            }
        ],
        "graph": {"generated_tus": [], "link_admissions": []},
    }

    result = convert_v2_manifest(manifest, "2" * 64)
    shared = json.loads(result.files[PurePosixPath("reprobit/interventions/shared-sample.json")])
    overlay = next(
        item for item in shared["interventions"] if item["family"] == "source_overlay_graph"
    )
    fields = {item["name"]: item["value"] for item in overlay["parameters"]}

    assert fields["semantic_claims"] == {"schema": 1, "bindings": []}


def test_migration_preserves_linker_payload_metadata_but_redacts_bytes() -> None:
    manifest = _manifest()
    function = manifest["translation_units"][0]["functions"][0]
    function["splice_class"] = "retail_exact_instruction_mosaic"
    function["instruction_self_permutation"] = {
        "kind": "commuting_xor_zero_stack_load_v1",
        "expected_linker_payload_count": 5,
        "expected_linker_payload_sha256": "7" * 64,
        "moves": [{"donor_bytes": "33ff"}],
    }

    result = convert_v2_manifest(manifest, "2" * 64)
    proof = json.loads(result.files[_tu_path(result, "proofs")])
    receipt = next(
        item
        for item in proof["expected_observations"]
        if item["family"] == "retail_exact_instruction_mosaic"
    )

    assert receipt["expected_values"] == {
        "expected_body_length": 12,
        "instruction_self_permutation.expected_linker_payload_count": 5,
        "instruction_self_permutation.expected_linker_payload_sha256": "7" * 64,
    }
    assert [item["source_path"] for item in receipt["redactions"]] == [
        "instruction_self_permutation.moves[0].donor_bytes"
    ]


def test_migration_rejects_overlapping_compiler_visible_seats() -> None:
    manifest = _manifest()
    manifest["toolchain"]["codegen_path_contract"].update(
        {
            "build_root": "/workspace/compiler",
            "compiler": "/workspace/compiler/wine/x86/cl",
        }
    )

    with pytest.raises(MigrationError, match="logical roots overlap"):
        convert_v2_manifest(manifest, "2" * 64)


def test_migration_rejects_noncanonical_legacy_path_contract() -> None:
    manifest = _manifest()
    manifest["toolchain"]["codegen_path_contract"]["build_root"] = "/workspace/../sample-build"

    with pytest.raises(MigrationError, match="build root is not canonical"):
        convert_v2_manifest(manifest, "2" * 64)


def test_duplicate_donor_ids_are_canonicalized() -> None:
    manifest = _manifest()
    unit = manifest["translation_units"][0]
    unit["donors"].append(dict(unit["donors"][0]))
    result = convert_v2_manifest(manifest, "2" * 64)
    shard = json.loads(result.files[_tu_path(result, "interventions")])
    donors = [item for item in shard["interventions"] if item["role"] == "donor"]
    assert len(donors) == 1
    fields = {item["name"]: item["value"] for item in donors[0]["parameters"]}
    assert fields["legacy_recipe_id"] == "donor_a"


def test_unknown_recipe_family_fails_closed() -> None:
    manifest = _manifest()
    manifest["translation_units"][0]["functions"][0]["splice_class"] = "unknown"
    with pytest.raises(MigrationError, match="unsupported recipe family"):
        convert_v2_manifest(manifest, "2" * 64)


def _large_v2_manifest() -> Path | None:
    for candidate in sorted(Path.cwd().parent.glob("*/tools/byte_identity_manifest.json")):
        project_root = candidate.parent.parent
        if candidate.stat().st_size > 1_000_000 and (project_root / ".git").exists():
            return candidate
    return None


def test_real_v2_manifest_round_trips_through_strict_v3(tmp_path: Path) -> None:
    source = _large_v2_manifest()
    if source is None:
        pytest.skip("large schema-v2 integration fixture is not present")
    legacy_manifest, _source_sha256 = load_legacy_manifest(source)
    assert "semantic_claims" not in legacy_manifest["source_overlay"]
    claims_path = source.with_name("reprobit_migration_semantic_claims.once.json")
    assert claims_path.is_file()
    claims_document = json.loads(claims_path.read_bytes())
    assert set(claims_document) == {"bindings", "schema"}
    expected_claims = claims_document["bindings"]
    assert len(expected_claims) == 14
    assert (
        sha256(
            json.dumps(expected_claims, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        == "5dab2c6a7bbffd4963c76805d350707ece04f0325c9f86598bc8e1e763d9af81"
    )

    result = migration_output(source, semantic_claims_path=claims_path)
    build_plan = json.loads(result.files[PurePosixPath("reprobit/build-plan.json")])
    dialect = build_plan["toolchain_policy"]["classic_overlay_dialect"]
    assert set(dialect) == {"qualified_member_probe_return_type"}
    assert isinstance(dialect["qualified_member_probe_return_type"], str)
    assert dialect["qualified_member_probe_return_type"]
    for relative, data in result.files.items():
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)

    bundle = load_project_tree(tmp_path, verify_source_authority=False)
    assert len(bundle.interventions) == result.intervention_count == 745
    assert sum(len(item.expected_observations) for item in bundle.proof_documents) == 745
    legacy = [item for item in bundle.interventions if item.kind == "legacy.oracle_install"]
    assert len(legacy) == 2
    assert sum(len(item.ranges) for item in legacy) == 23
    assert sum(item.byte_count for item in legacy) == 572
    assert len(bundle.spec.authenticity.legacy_allowlist) == 2
    assert sum(len(data) for data in result.files.values()) < source.stat().st_size
    assert set(CostModel._classic_classes) == set(ClassicRecipeFamily) - {
        ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION
    }
    assert calculate_cost(bundle.interventions).project_total > 0

    migrated_claims: list[dict[str, object]] = []
    for relative, data in result.files.items():
        if not str(relative).startswith("reprobit/interventions/shared-"):
            continue
        document = json.loads(data)
        for intervention in document["interventions"]:
            if intervention.get("family") != "source_overlay_graph":
                continue
            fields = {item["name"]: item["value"] for item in intervention["parameters"]}
            migrated_claims.extend(fields["semantic_claims"]["bindings"])
    claim_key = lambda item: (  # noqa: E731 - concise canonical parity key
        str(item["operation"]).casefold(),
        int(item["leaf"]),
        str(item["kind"]),
    )
    assert sorted(migrated_claims, key=claim_key) == sorted(expected_claims, key=claim_key)

    redactions = [
        redaction
        for document in bundle.proof_documents
        for receipt in document.expected_observations
        for redaction in receipt.redactions
    ]
    assert len(redactions) == 194
    assert all(redaction.evidence_digest.algorithm == "sha256" for redaction in redactions)
    assert all("linker_payload" not in redaction.source_path for redaction in redactions)
    self_permutations = [
        receipt
        for document in bundle.proof_documents
        for receipt in document.expected_observations
        if "instruction_self_permutation.expected_linker_payload_count" in receipt.expected_values
    ]
    assert len(self_permutations) == 2
    assert {
        (
            receipt.expected_values["instruction_self_permutation.expected_linker_payload_count"],
            receipt.expected_values["instruction_self_permutation.expected_linker_payload_sha256"],
        )
        for receipt in self_permutations
    } == {
        (5, "7893a112afbd4cda848d521a6efb811d8e293527e40f5ad7d1a2deb76e078cb3"),
        (67, "cfd4f920c9c263b17dd5b35e0a2f9ecff16e4838d04372da0616fcfd1ccfc79e"),
    }
    import_order = next(
        item
        for item in bundle.interventions
        if getattr(item, "family", None) is ClassicRecipeFamily.IMAGE_LINK_ORDER
    )
    fields = {item.name: item.value for item in import_order.parameters}
    assert set(fields) == {"import_order"}
    assert fields["import_order"]["schema"] == "pe32_import_order_v1"
    assert fields["import_order"]["imports"]


def test_real_v2_manifest_rejects_a_conflicting_overlay_dialect_lock() -> None:
    source = _large_v2_manifest()
    if source is None:
        pytest.skip("large schema-v2 integration fixture is not present")
    manifest, source_sha256 = load_legacy_manifest(source)
    manifest["toolchain"]["classic_overlay_dialect"] = {
        "qualified_member_probe_return_type": "long"
    }

    with pytest.raises(MigrationError, match="locked classic overlay dialect differs"):
        convert_v2_manifest(
            manifest,
            source_sha256,
            source_root=source.parent.parent,
        )
