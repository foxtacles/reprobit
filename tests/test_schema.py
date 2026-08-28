from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from reprobit.model import Digest, Scope
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerNode,
    ProducerRole,
    toolchain_document_digest,
)
from reprobit.schema import (
    BuildPlanDocument,
    ClassicArchiveAuthority,
    ClassicTargetGate,
    ClassicTranslationUnitPlan,
    InterventionDocument,
    LinkOrderingIntervention,
    LogicalPathProfile,
    ProjectBundle,
    SchemaError,
    SchemaVersionError,
    SourceManifestDocument,
    SourceManifestEntry,
    load_project,
    load_project_tree,
    project_document_schemas,
    schema_catalog,
    source_manifest_digest,
    write_json_schema,
    write_project_document_schemas,
)
from reprobit.strict_json import (
    DuplicateKeyError,
    NonFiniteNumberError,
    canonical_json,
    strict_loads,
)

PROJECT_TOML = """\
schema_version = 3
project_id = "sample"

[build]
kind = "producer-graph"

[toolchain]
profile = "compiler-42"

[paths]
source = "R:\\\\src"
build = "R:\\\\build"
toolchain = "R:\\\\toolchain"

[[targets]]
id = "program"
artifact = "build/program.exe"
oracle = "references/program.exe"
"""


def sha(seed: bytes) -> dict[str, str]:
    return Digest.from_bytes(seed).model_dump(mode="json")


def test_build_target_can_lead_with_a_digit_without_widening_internal_ids() -> None:
    assert (
        ClassicTranslationUnitPlan(
            id="tu_sample",
            target_id="program",
            build_target="3dmanager",
            source="src/sample.cpp",
            source_digest=Digest(value="0" * 64),
            mode="compose",
        ).build_target
        == "3dmanager"
    )
    with pytest.raises(ValidationError, match="String should match pattern"):
        ClassicTranslationUnitPlan(
            id="tu_sample",
            target_id="3program",
            build_target="3dmanager",
            source="src/sample.cpp",
            source_digest=Digest(value="0" * 64),
            mode="compose",
        )


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value))


def create_tree(root: Path) -> None:
    (root / "reprobit.toml").write_text(
        PROJECT_TOML,
        encoding="utf-8",
        newline="\n",
    )
    write_json(
        root / "reprobit/source-manifest.json",
        {
            "schema_version": 3,
            "algorithm": "portable-source-v1",
            "complete": True,
            "entries": [
                {
                    "path": "reprobit.toml",
                    "size": len(PROJECT_TOML.encode("utf-8")),
                    "digest": sha(PROJECT_TOML.encode("utf-8")),
                }
            ],
        },
    )
    write_json(
        root / "reprobit/toolchain.lock.json",
        {
            "schema_version": 3,
            "profile": "compiler-42",
            "adapter": "classic-msvc",
            "release": "4.2",
            "tools": [
                {
                    "id": "compiler",
                    "path": "tools/compiler.exe",
                    "digest": sha(b"compiler"),
                    "size": 10,
                }
            ],
            "runtime_files": [],
        },
    )
    write_json(
        root / "reprobit/interventions/shared.json",
        {"schema_version": 3, "target_id": "program", "interventions": []},
    )
    write_json(
        root / "reprobit/proofs/shared.proof.json",
        {
            "schema_version": 3,
            "target_id": "program",
            "expected_observations": [],
        },
    )
    write_json(
        root / "reprobit/oracles/program.json",
        {
            "schema_version": 3,
            "target_id": "program",
            "image_size": 10,
            "image_digest": sha(b"reference"),
            "functions": [],
        },
    )


def test_strict_json_rejects_ambiguous_documents() -> None:
    with pytest.raises(DuplicateKeyError, match="duplicate"):
        strict_loads('{"schema_version":3,"schema_version":2}')
    with pytest.raises(NonFiniteNumberError, match="non-finite"):
        strict_loads('{"seconds":NaN}')
    assert canonical_json({"z": 1, "a": [2, 3]}) == b'{"a":[2,3],"z":1}\n'


def test_load_project_is_v3_only_and_forbids_unknown_fields(tmp_path: Path) -> None:
    path = tmp_path / "reprobit.toml"
    path.write_text(PROJECT_TOML, encoding="utf-8")
    project = load_project(path)
    assert project.project_id == "sample"
    assert project.targets[0].id == "program"

    path.write_text(PROJECT_TOML.replace('kind = "producer-graph"', 'kind = "cmake"'))
    with pytest.raises(SchemaError, match="cmake"):
        load_project(path)

    path.write_text(PROJECT_TOML.replace("schema_version = 3", "schema_version = 2"))
    with pytest.raises(SchemaVersionError, match="only schema 3"):
        load_project(path)

    path.write_text(PROJECT_TOML + '\nunknown = "field"\n')
    with pytest.raises(SchemaError, match="Extra inputs are not permitted"):
        load_project(path)

    path.write_text(
        PROJECT_TOML.replace(
            "[[targets]]",
            '[verifier]\nkind = "reccmp"\nexecutable = "tools/reccmp"\n\n[[targets]]',
        ),
        encoding="utf-8",
    )
    with pytest.raises(SchemaError, match="literal"):
        load_project(path)


def test_project_relative_paths_are_canonicalized_to_portable_separators(
    tmp_path: Path,
) -> None:
    path = tmp_path / "reprobit.toml"
    path.write_text(
        PROJECT_TOML.replace(
            'artifact = "build/program.exe"',
            'artifact = "build\\\\program.exe"',
        ),
        encoding="utf-8",
    )
    assert load_project(path).targets[0].artifact == "build/program.exe"


@pytest.mark.parametrize(
    ("source", "build"),
    (
        (r"R:\Source", r"R:\source\build"),
        (r"R:\source\nested", r"r:\SOURCE"),
    ),
)
def test_logical_path_profile_rejects_case_insensitive_ancestor_overlap(
    source: str,
    build: str,
) -> None:
    with pytest.raises(ValidationError, match="must not overlap"):
        LogicalPathProfile(
            source=source,
            build=build,
            toolchain=r"R:\toolchain",
        )


def test_logical_path_profile_uses_dos_segment_boundaries_for_overlap() -> None:
    profile = LogicalPathProfile(
        source=r"R:\source",
        build=r"R:\source-cache",
        toolchain=r"R:\toolchain",
    )
    assert profile.build == r"R:\source-cache"


def test_logical_path_profile_requires_one_shared_drive() -> None:
    with pytest.raises(ValidationError, match="must share one drive"):
        LogicalPathProfile(
            source=r"R:\source",
            build=r"S:\build",
            toolchain=r"R:\toolchain",
        )


def test_intervention_document_is_closed_and_scope_consistent() -> None:
    intervention = LinkOrderingIntervention(
        id="order-main",
        scope=Scope(target="program"),
        rationale="preserve deterministic library member order",
        item_ids=("first", "second"),
    )
    document = InterventionDocument(
        schema_version=3,
        target_id="program",
        interventions=(intervention,),
    )
    assert document.interventions[0].kind == "link_ordering"
    with pytest.raises(ValidationError, match="different target"):
        InterventionDocument(
            schema_version=3,
            target_id="other",
            interventions=(intervention,),
        )
    scoped = intervention.model_copy(
        update={"scope": Scope(target="program", translation_unit="unit-main")}
    )
    with pytest.raises(ValidationError, match="requires a translation-unit shard"):
        InterventionDocument(
            schema_version=3,
            target_id="program",
            interventions=(scoped,),
        )

    invalid = document.model_dump(mode="json")
    invalid["interventions"][0]["script"] = "arbitrary.py"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        InterventionDocument.model_validate_json(canonical_json(invalid))


def test_load_project_tree_cross_validates_and_rejects_duplicates(tmp_path: Path) -> None:
    create_tree(tmp_path)
    bundle = load_project_tree(tmp_path)
    assert bundle.spec.project_id == "sample"
    assert bundle.toolchain_lock.release == "4.2"
    assert len(bundle.oracle_documents) == 1

    oracle = tmp_path / "reprobit/oracles/program.json"
    oracle.write_text('{"schema_version":3,"target_id":"program","target_id":"other"}')
    with pytest.raises(SchemaError, match="duplicate JSON object key"):
        load_project_tree(tmp_path)


def test_project_tree_rejects_ghost_cost_beneficiaries(tmp_path: Path) -> None:
    create_tree(tmp_path)
    intervention_path = tmp_path / "reprobit/interventions/shared.json"
    document = {
        "schema_version": 3,
        "target_id": "program",
        "interventions": [
            {
                "id": "real-function",
                "version": 1,
                "kind": "state_carrier",
                "scope": {
                    "target": "program",
                    "translation_unit": "main",
                    "function": "real()",
                },
                "rationale": "anchor one genuine function allocation scope",
                "dependencies": [],
                "beneficiaries": [],
                "carrier": "declaration",
            },
            {
                "id": "shared-order",
                "version": 1,
                "kind": "link_ordering",
                "scope": {"target": "program"},
                "rationale": "exercise shared cost allocation validation",
                "dependencies": [],
                "beneficiaries": [
                    {
                        "target": "program",
                        "translation_unit": "main",
                        "function": "ghost()",
                    }
                ],
                "item_ids": ["one", "two"],
            },
        ],
    }
    function_intervention = document["interventions"].pop(0)  # type: ignore[union-attr]
    write_json(
        tmp_path / "reprobit/interventions/unit-main.json",
        {
            "schema_version": 3,
            "target_id": "program",
            "translation_unit_id": "main",
            "interventions": [function_intervention],
        },
    )
    write_json(intervention_path, document)
    with pytest.raises(SchemaError, match="unknown function scope"):
        load_project_tree(tmp_path)

    document["interventions"][0]["beneficiaries"][0]["function"] = "real()"  # type: ignore[index]
    write_json(intervention_path, document)
    assert len(load_project_tree(tmp_path).interventions) == 2


def test_project_tree_binds_closed_producer_graph(tmp_path: Path) -> None:
    create_tree(tmp_path)
    baseline = load_project_tree(tmp_path)
    assert baseline.source_manifest is not None
    graph = {
        "schema_version": 1,
        "source_manifest_digest": source_manifest_digest(baseline.source_manifest).model_dump(
            mode="json"
        ),
        "toolchain_lock_digest": toolchain_document_digest(baseline.toolchain_lock).model_dump(
            mode="json"
        ),
        "path_profile_id": baseline.spec.paths.id,
        "extractor": "cmake-unix-makefiles-v1",
        "nodes": [
            {
                "id": "linker.program",
                "role": "linker",
                "owner": "program",
                "target_id": "program",
                "arguments": ["/out:${BUILD}/program.exe"],
                "inputs": [],
                "outputs": ["build/program.exe"],
                "depends_on": [],
            }
        ],
    }
    graph_path = tmp_path / "reprobit/producer-graph.json"
    write_json(graph_path, graph)
    bundle = load_project_tree(tmp_path)
    assert bundle.producer_graph is not None
    assert bundle.producer_graph.nodes[0].target_id == "program"

    graph["nodes"][0]["outputs"] = ["build/another.exe"]
    graph["nodes"][0]["arguments"] = ["/out:${BUILD}/another.exe"]
    write_json(graph_path, graph)
    with pytest.raises(SchemaError, match="does not publish the exact project artifact"):
        load_project_tree(tmp_path)

    graph["nodes"][0]["outputs"] = ["build/program.exe"]
    graph["nodes"][0]["arguments"] = ["/out:${BUILD}/program.exe"]
    graph["path_profile_id"] = "another-profile"
    write_json(graph_path, graph)
    with pytest.raises(SchemaError, match="logical-path profile differs"):
        load_project_tree(tmp_path)


def test_quarantine_archive_edges_require_exact_build_plan_and_source_pins(
    tmp_path: Path,
) -> None:
    create_tree(tmp_path)
    baseline = load_project_tree(tmp_path)
    assert baseline.source_manifest is not None
    payload = b"explicit third-party archive fixture"
    archive_path = "vendor/payload.lib"
    manifest = SourceManifestDocument(
        schema_version=3,
        complete=True,
        entries=(
            *baseline.source_manifest.entries,
            SourceManifestEntry(
                path=archive_path,
                size=len(payload),
                digest=Digest.from_bytes(payload),
            ),
        ),
    )
    authority = ClassicArchiveAuthority.model_validate_json(
        canonical_json(
            {
                "identity": "FixtureArchive",
                "imported_target": "Fixture::Archive",
                "kind": "third_party_reconstructed_archive",
                "source": archive_path,
                "source_sha256": Digest.from_bytes(payload).value,
                "payload_policy": (
                    "retail_bytes_explicitly_allowed_for_named_third_party_archive_only"
                ),
                "completion": {
                    "state": "authorized_exact_archive_materialization_enabled",
                    "may_supply_linker_payload": True,
                    "reason": "exercise an explicit finite quarantine authority",
                },
                "link_contract": [
                    {
                        "target": "program",
                        "direct_link_sequence": ["Fixture::Archive"],
                        "occurrences": 1,
                    }
                ],
            }
        )
    )
    plan = BuildPlanDocument(
        schema_version=3,
        source_manifest_digest=source_manifest_digest(manifest),
        phase=None,
        translation_units=(),
        source_overlay_digest=Digest.from_bytes(b"empty overlay"),
        source_overlay_interventions=(),
        archives=(authority,),
        terminal_producers={},
        execution_backends={},
        toolchain_policy={},
        target_policies=[],
        target_gates=(
            ClassicTargetGate(target_id="program", build_target="program", completion={}),
        ),
    )
    graph = ProducerGraphDocument(
        schema_version=1,
        source_manifest_digest=source_manifest_digest(manifest),
        toolchain_lock_digest=toolchain_document_digest(baseline.toolchain_lock),
        path_profile_id=baseline.spec.paths.id,
        extractor="cmake-unix-makefiles-v1",
        nodes=(
            ProducerNode(
                id="linker.program",
                role=ProducerRole.LINKER,
                owner="program",
                target_id="program",
                arguments=(
                    "${SOURCE}/vendor/payload.lib",
                    "/out:${BUILD}/program.exe",
                ),
                inputs=("quarantine-archive/vendor/payload.lib",),
                outputs=("build/program.exe",),
            ),
        ),
    )
    values = {
        "root": baseline.root,
        "spec": baseline.spec,
        "toolchain_lock": baseline.toolchain_lock,
        "source_manifest": manifest,
        "build_plan": plan,
        "producer_graph": graph,
        "intervention_documents": baseline.intervention_documents,
        "proof_documents": baseline.proof_documents,
        "oracle_documents": baseline.oracle_documents,
    }
    assert ProjectBundle(**values).build_plan == plan

    bad_authority = authority.model_copy(update={"source_sha256": "0" * 64})
    bad_plan = plan.model_copy(update={"archives": (bad_authority,)})
    with pytest.raises(ValidationError, match="digest differs from source authority"):
        ProjectBundle(**{**values, "build_plan": bad_plan})
    with pytest.raises(ValidationError, match="do not match build-plan authority"):
        ProjectBundle(**{**values, "build_plan": plan.model_copy(update={"archives": ()})})

    repeated_node = ProducerNode(
        id="linker.program",
        role=ProducerRole.LINKER,
        owner="program",
        target_id="program",
        arguments=(
            "${SOURCE}/vendor/payload.lib",
            "${SOURCE}/vendor/payload.lib",
            "/out:${BUILD}/program.exe",
        ),
        inputs=("quarantine-archive/vendor/payload.lib",),
        outputs=("build/program.exe",),
    )
    repeated_graph = graph.model_copy(update={"nodes": (repeated_node,)})
    with pytest.raises(ValidationError, match="occurrence count differs"):
        ProjectBundle(**{**values, "producer_graph": repeated_graph})


def test_generated_schema_contains_all_document_models(tmp_path: Path) -> None:
    schema = schema_catalog()
    encoded = canonical_json(schema)
    assert schema["$id"] == "urn:reprobit:schema:catalog:3"
    assert b'"ProjectSpec"' in encoded
    assert b'"LegacyOracleInstallIntervention"' in encoded
    assert b'"ProducerGraphDocument"' in encoded
    destination = tmp_path / "catalog.schema.json"
    write_json_schema(destination)
    assert json.loads(destination.read_bytes())["title"] == "SchemaCatalog"


def test_generated_document_schemas_have_usable_roots_and_stable_ids(
    tmp_path: Path,
) -> None:
    schemas = project_document_schemas()
    expected_titles = {
        "project-v3.schema.json": "ProjectSpec",
        "toolchain-lock-v3.schema.json": "ToolchainLock",
        "source-manifest-v3.schema.json": "SourceManifestDocument",
        "build-plan-v3.schema.json": "BuildPlanDocument",
        "producer-graph-v2.schema.json": "ProducerGraphDocument",
        "intervention-document-v3.schema.json": "InterventionDocument",
        "proof-document-v3.schema.json": "ProofDocument",
        "oracle-document-v3.schema.json": "OracleDocument",
        "catalog-v3.schema.json": "SchemaCatalog",
    }
    assert {name: schema["title"] for name, schema in schemas.items()} == expected_titles
    assert all(schema["$schema"].endswith("/draft/2020-12/schema") for schema in schemas.values())
    assert len({schema["$id"] for schema in schemas.values()}) == len(schemas)

    write_project_document_schemas(tmp_path)
    assert {path.name for path in tmp_path.glob("*.schema.json")} == set(expected_titles)
    for name, schema in schemas.items():
        assert (tmp_path / name).read_bytes() == canonical_json(schema)


def test_generated_schemas_describe_the_project_overlay_primary_boundary() -> None:
    schemas = project_document_schemas()
    for name in (
        "intervention-document-v3.schema.json",
        "proof-document-v3.schema.json",
        "catalog-v3.schema.json",
    ):
        family_description = schemas[name]["$defs"]["ClassicRecipeFamily"]["description"]
        assert "source_overlay_graph" in family_description
        assert "certified-project-overlay" in family_description
        assert "donor_source_overlay" in family_description
        assert "donor-private" in family_description

    intervention_description = schemas["intervention-document-v3.schema.json"]["$defs"][
        "ClassicRecipeIntervention"
    ]["description"]
    assert "typed source evidence" in intervention_description
    assert "sparse declaration-counterfactual compiler audits" in intervention_description
    assert "effective invocations" in intervention_description

    manifest_schema = schemas["source-manifest-v3.schema.json"]
    assert "clean-source authority" in manifest_schema["description"]
    assert "clean source baseline" in manifest_schema["$defs"]["SourceManifestEntry"]["description"]

    build_plan_description = schemas["build-plan-v3.schema.json"]["description"]
    assert "source_overlay_graph" in build_plan_description
    assert "donor_source_overlay" in build_plan_description
    assert "primary compiler seat" in build_plan_description
