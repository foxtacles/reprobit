from __future__ import annotations

import json
import random
from pathlib import Path, PurePosixPath

import pytest
from pydantic import ValidationError

from reprobit.model import Digest, Scope
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerNode,
    ProducerRole,
    toolchain_document_digest,
)
from reprobit.project_loader import (
    load_project,
    load_project_tree,
    validate_project_files,
)
from reprobit.schema import (
    BuildPlanDocument,
    ClassicArchiveAuthority,
    ClassicDebugCompanionPaths,
    ClassicField,
    ClassicGroupOrderPlan,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    ClassicTargetGate,
    ClassicTranslationUnitPlan,
    InterventionDocument,
    LinkOrderingIntervention,
    LogicalPathProfile,
    OracleDocument,
    ProjectBundle,
    ProofDocument,
    SchemaError,
    SchemaVersionError,
    SourceManifestDocument,
    SourceManifestEntry,
    _ProtectedPathClaims,
    classic_debug_companion_paths,
    project_document_schemas,
    schema_catalog,
    source_manifest_digest,
    write_json_schema,
    write_project_document_schemas,
)
from reprobit.strict_json import (
    DuplicateKeyError,
    NonFiniteNumberError,
    StrictJSONError,
    canonical_json,
    strict_load_bytes,
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


def _build_plan_with_link_options(options: object = ()) -> BuildPlanDocument:
    return BuildPlanDocument(
        schema_version=3,
        source_manifest_digest=Digest.from_bytes(b"source"),
        translation_units=(),
        source_overlay_digest=Digest.from_bytes(b"overlay"),
        source_overlay_interventions=(),
        archives=(),
        analysis_link_options=options,  # type: ignore[arg-type]
        target_gates=(),
    )


def test_analysis_link_options_are_json_native_and_closed() -> None:
    plan = _build_plan_with_link_options(("/DEBUG",))
    reparsed = BuildPlanDocument.model_validate_json(plan.model_dump_json())
    assert reparsed.analysis_link_options == ("/DEBUG",)
    assert _build_plan_with_link_options().analysis_link_options == ()


@pytest.mark.parametrize(
    "options",
    (["/debug"], ["/DEBUG", "/DEBUG"], "/DEBUG"),
)
def test_analysis_link_options_reject_malformed_or_widened_values(options: object) -> None:
    with pytest.raises(ValidationError):
        _build_plan_with_link_options(options)


def test_debug_companion_paths_are_grouped_beside_the_exact_artifact(tmp_path: Path) -> None:
    create_tree(tmp_path)
    baseline = load_project_tree(tmp_path)
    assert baseline.source_manifest is not None
    plan = _build_plan_with_link_options(("/DEBUG",)).model_copy(
        update={"source_manifest_digest": source_manifest_digest(baseline.source_manifest)}
    )
    bundle = baseline.model_copy(update={"build_plan": plan})

    assert classic_debug_companion_paths(bundle) == (
        ClassicDebugCompanionPaths(
            "program",
            "build/reprobit-debug/program.exe",
            "build/reprobit-debug/program.PDB",
        ),
    )


def test_debug_companion_path_cannot_alias_a_verification_oracle(tmp_path: Path) -> None:
    create_tree(tmp_path)
    baseline = load_project_tree(tmp_path)
    assert baseline.source_manifest is not None
    target = baseline.spec.targets[0]
    spec = baseline.spec.model_copy(
        update={
            "targets": (target.model_copy(update={"oracle": "build/reprobit-debug/program.PDB"}),)
        }
    )
    plan = _build_plan_with_link_options(("/DEBUG",)).model_copy(
        update={"source_manifest_digest": source_manifest_digest(baseline.source_manifest)}
    )
    bundle = baseline.model_copy(update={"spec": spec, "build_plan": plan})

    with pytest.raises(ValueError, match="aliases protected verification oracle"):
        classic_debug_companion_paths(bundle)


def _companion_bundle(
    tmp_path: Path, *, oracle: str | None = None, extra_sources: tuple[str, ...] = ()
) -> ProjectBundle:
    tmp_path.mkdir(exist_ok=True)
    create_tree(tmp_path)
    baseline = load_project_tree(tmp_path)
    assert baseline.source_manifest is not None
    entries = list(baseline.source_manifest.entries)
    entries.extend(
        SourceManifestEntry(path=path, size=1, digest=Digest(value="1" * 64))
        for path in extra_sources
    )
    manifest = baseline.source_manifest.model_copy(
        update={
            "entries": tuple(sorted(entries, key=lambda item: (item.path.casefold(), item.path)))
        }
    )
    plan = _build_plan_with_link_options(("/DEBUG",)).model_copy(
        update={"source_manifest_digest": source_manifest_digest(manifest)}
    )
    spec = baseline.spec
    if oracle is not None:
        target = spec.targets[0]
        spec = spec.model_copy(update={"targets": (target.model_copy(update={"oracle": oracle}),)})
    return baseline.model_copy(
        update={"spec": spec, "source_manifest": manifest, "build_plan": plan}
    )


def test_debug_companion_path_cannot_sit_below_or_above_a_protected_path(
    tmp_path: Path,
) -> None:
    # A source file below the derived image path: the image would be its directory.
    below = _companion_bundle(tmp_path, extra_sources=("build/reprobit-debug/program.exe/a.c",))
    with pytest.raises(
        ValueError,
        match=r"'build/reprobit-debug/program\.exe' overlaps protected source-manifest entry "
        r"'build/reprobit-debug/program\.exe/a\.c'",
    ):
        classic_debug_companion_paths(below)

    # A source file named like the companion directory: the image would sit inside a file.
    above = _companion_bundle(tmp_path / "above", extra_sources=("build/REPROBIT-DEBUG",))
    with pytest.raises(
        ValueError,
        match=r"'build/reprobit-debug/program\.exe' overlaps protected source-manifest entry "
        r"'build/REPROBIT-DEBUG'",
    ):
        classic_debug_companion_paths(above)

    # Several earlier claims overlap: the earliest claimed (the oracle) is the one named.
    earliest = _companion_bundle(
        tmp_path / "earliest",
        oracle="build/reprobit-debug/program.PDB/oracle.bin",
        extra_sources=("build/reprobit-debug/program.PDB/a.c",),
    )
    with pytest.raises(
        ValueError,
        match=r"'build/reprobit-debug/program\.PDB' overlaps protected verification oracle "
        r"for 'program'",
    ):
        classic_debug_companion_paths(earliest)


def _scan_every_claim(paths: list[str]) -> str | None:
    """The full arrival-order scan the ancestor index must reproduce exactly."""

    claims: dict[str, str] = {}
    for ordinal, relative in enumerate(paths):
        owner = f"owner {ordinal}"
        folded = relative.replace("\\", "/").casefold()
        previous = claims.get(folded)
        if previous is not None:
            return f"debug-companion path {relative!r} aliases protected {previous}"
        for previous_path, previous_owner in claims.items():
            if folded.startswith(previous_path + "/") or previous_path.startswith(folded + "/"):
                return f"debug-companion path {relative!r} overlaps protected {previous_owner}"
        claims[folded] = owner
    return None


def test_protected_path_claims_report_exactly_what_a_full_scan_reports() -> None:
    rng = random.Random(20260901)
    parts = ("a", "B", "c", "dir", "x.cpp", "", "A")
    trials = 0
    outcomes = {"accepted": 0, "aliases": 0, "overlaps": 0}
    for _ in range(4000):
        paths = [
            rng.choice(("/", "\\")).join(rng.choice(parts) for _ in range(rng.randint(1, 4)))
            + rng.choice(("", "", "/"))
            for _ in range(rng.randint(1, 8))
        ]
        expected = _scan_every_claim(paths)
        claims = _ProtectedPathClaims()
        received = None
        for ordinal, relative in enumerate(paths):
            try:
                claims.claim(relative, f"owner {ordinal}")
            except ValueError as error:
                received = str(error)
                break
        assert received == expected, paths
        trials += 1
        if expected is None:
            outcomes["accepted"] += 1
        elif " aliases " in expected:
            outcomes["aliases"] += 1
        else:
            outcomes["overlaps"] += 1
    assert trials == 4000
    assert all(count > 100 for count in outcomes.values()), outcomes


def test_build_target_can_lead_with_a_digit_without_widening_internal_ids() -> None:
    assert (
        ClassicTranslationUnitPlan(
            id="tu_sample",
            target_id="program",
            build_target="3dmanager",
            source="src/sample.cpp",
            source_digest=Digest(value="0" * 64),
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
        )


def test_translation_unit_group_order_is_explicit_and_closed() -> None:
    transform = ClassicGroupOrderPlan(
        operation="restore_comdat_group_order",
        orders=(("?first@@YAXXZ", "?second@@YAXXZ"),),
    )
    unit = ClassicTranslationUnitPlan(
        id="tu_sample",
        target_id="program",
        build_target="program",
        source="src/sample.cpp",
        source_digest=Digest(value="0" * 64),
        group_order=transform,
    )
    assert unit.group_order == transform

    with pytest.raises(ValidationError, match="must be unique"):
        ClassicGroupOrderPlan(
            operation="swap_comdat_group_order",
            orders=(("?same@@YAXXZ", "?same@@YAXXZ"),),
        )


@pytest.mark.parametrize(
    "obsolete",
    (
        "migration_source_digest",
        "phase",
        "terminal_producers",
        "execution_backends",
        "target_policies",
    ),
)
def test_build_plan_rejects_obsolete_source_fields(obsolete: str) -> None:
    payload = _build_plan_with_link_options().model_dump(mode="json")
    payload[obsolete] = None
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        BuildPlanDocument.model_validate(payload)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value))


def create_tree(root: Path) -> None:
    (root / "reprobit.toml").write_text(
        PROJECT_TOML,
        encoding="utf-8",
        newline="\n",
    )
    source = b"int fixture;\n"
    (root / "src").mkdir()
    (root / "src/input.cpp").write_bytes(source)
    write_json(
        root / "reprobit/source-manifest.json",
        {
            "schema_version": 3,
            "algorithm": "portable-source-v1",
            "complete": True,
            "entries": [
                {
                    "path": "src/input.cpp",
                    "size": len(source),
                    "digest": sha(source),
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


def test_project_tree_rejects_entrypoint_as_source_authority(tmp_path: Path) -> None:
    create_tree(tmp_path)
    entrypoint = (tmp_path / "reprobit.toml").read_bytes()
    write_json(
        tmp_path / "reprobit/source-manifest.json",
        {
            "schema_version": 3,
            "complete": True,
            "entries": [
                {
                    "path": "reprobit.toml",
                    "size": len(entrypoint),
                    "digest": sha(entrypoint),
                }
            ],
        },
    )

    with pytest.raises(SchemaError, match=r"control, output, or oracle path 'reprobit\.toml'"):
        load_project_tree(tmp_path)


@pytest.mark.parametrize(
    ("role", "scope", "symbol", "message"),
    (
        (
            ClassicRecipeRole.FUNCTION,
            Scope(target="program", translation_unit="main"),
            "work()",
            "exact symbol",
        ),
        (
            ClassicRecipeRole.FUNCTION,
            Scope(target="program", translation_unit="main", function="other()"),
            "work()",
            "exact symbol",
        ),
        (
            ClassicRecipeRole.DONOR,
            Scope(target="program"),
            None,
            "translation-unit scope",
        ),
        (
            ClassicRecipeRole.DONOR,
            Scope(target="program", translation_unit="main", function="work()"),
            None,
            "cannot have function scope",
        ),
        (
            ClassicRecipeRole.PROJECT,
            Scope(target="program", translation_unit="main"),
            None,
            "requires target scope",
        ),
    ),
)
def test_classic_recipe_role_requires_its_authoritative_scope(
    role: ClassicRecipeRole,
    scope: Scope,
    symbol: str | None,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        ClassicRecipeIntervention(
            id="classic",
            scope=scope,
            rationale="scope contract fixture",
            family=ClassicRecipeFamily.DECLARATION_SHAPE,
            role=role,
            build_target="program",
            symbol=symbol,
        )


@pytest.mark.parametrize("dependencies", [(), ("first", "second")])
def test_classic_function_recipe_requires_one_primary_donor(
    dependencies: tuple[str, ...],
) -> None:
    with pytest.raises(ValidationError, match="requires one primary donor"):
        ClassicRecipeIntervention(
            id="classic",
            scope=Scope(
                target="program",
                translation_unit="main",
                function="work()",
            ),
            rationale="primary donor contract fixture",
            dependencies=dependencies,
            family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
            role=ClassicRecipeRole.FUNCTION,
            build_target="program",
            symbol="work()",
        )


def test_classic_donor_beneficiaries_cover_primary_and_auxiliary_consumers_once(
    tmp_path: Path,
) -> None:
    create_tree(tmp_path)
    baseline = load_project_tree(tmp_path)
    function_scope = Scope(
        target="program",
        translation_unit="main",
        function="work()",
    )

    def bundle_with(
        primary_beneficiaries: tuple[Scope, ...],
        auxiliary_beneficiaries: tuple[Scope, ...],
    ) -> ProjectBundle:
        donor = ClassicRecipeIntervention(
            id="donor",
            scope=Scope(target="program", translation_unit="main"),
            rationale="dependency allocation fixture",
            family=ClassicRecipeFamily.DECLARATION_SHAPE,
            role=ClassicRecipeRole.DONOR,
            build_target="program",
            beneficiaries=primary_beneficiaries,
        )
        auxiliary = ClassicRecipeIntervention(
            id="auxiliary",
            scope=Scope(target="program", translation_unit="main"),
            rationale="auxiliary donor allocation fixture",
            family=ClassicRecipeFamily.PAD_SHAPE,
            role=ClassicRecipeRole.DONOR,
            build_target="program",
            beneficiaries=auxiliary_beneficiaries,
        )
        function = ClassicRecipeIntervention(
            id="function",
            scope=function_scope,
            rationale="dependency allocation fixture",
            dependencies=(donor.id,),
            family=ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC,
            role=ClassicRecipeRole.FUNCTION,
            build_target="program",
            symbol="work()",
            parameters=(
                ClassicField(
                    name="donor_variants",
                    value=[{"donor": auxiliary.id}],
                ),
                ClassicField(name="instruction_donor", value=auxiliary.id),
                ClassicField(name="target_donor", value=auxiliary.id),
            ),
        )
        return ProjectBundle(
            root=baseline.root,
            spec=baseline.spec,
            toolchain_lock=baseline.toolchain_lock,
            source_manifest=baseline.source_manifest,
            build_plan=baseline.build_plan,
            producer_graph=baseline.producer_graph,
            intervention_documents=(
                InterventionDocument(
                    schema_version=3,
                    target_id="program",
                    translation_unit_id="main",
                    build_target="program",
                    interventions=(donor, auxiliary, function),
                ),
            ),
            proof_documents=(
                ProofDocument(
                    schema_version=3,
                    target_id="program",
                    translation_unit_id="main",
                    expected_observations=(
                        ClassicProofReceipt(
                            id="donor-proof",
                            intervention_id=donor.id,
                            family=donor.family,
                        ),
                        ClassicProofReceipt(
                            id="auxiliary-proof",
                            intervention_id=auxiliary.id,
                            family=auxiliary.family,
                        ),
                        ClassicProofReceipt(
                            id="function-proof",
                            intervention_id=function.id,
                            family=function.family,
                            expected_values={"complete_donor": auxiliary.id},
                        ),
                    ),
                ),
            ),
            oracle_documents=baseline.oracle_documents,
        )

    accepted = bundle_with((function_scope,), (function_scope,))
    by_id = {item.id: item for item in accepted.interventions}
    assert by_id["donor"].beneficiaries == (function_scope,)
    assert by_id["auxiliary"].beneficiaries == (function_scope,)
    with pytest.raises(ValidationError, match="runtime consumers"):
        bundle_with((function_scope,), ())


def test_strict_json_rejects_ambiguous_documents() -> None:
    with pytest.raises(DuplicateKeyError, match="duplicate"):
        strict_loads('{"schema_version":3,"schema_version":2}')
    with pytest.raises(NonFiniteNumberError, match="non-finite"):
        strict_loads('{"seconds":NaN}')
    assert canonical_json({"z": 1, "a": [2, 3]}) == b'{"a":[2,3],"z":1}\n'


def test_strict_load_bytes_gates_the_file_and_returns_its_own_bytes(tmp_path: Path) -> None:
    path = tmp_path / "record.json"
    original = b'{\n  "z": 1,\n  "a": [2, 3.5e1, "\\u00e9", "\xc3\xa9"]\n}\n'
    path.write_bytes(original)
    assert strict_load_bytes(path) == original

    # json.loads reads a byte-order mark and UTF-16/32 through encoding detection;
    # the gate hands the second parser plain UTF-8 so those files stay accepted.
    for encoded in (b"\xef\xbb\xbf" + original, original.decode().encode("utf-16")):
        path.write_bytes(encoded)
        assert strict_load_bytes(path) == original

    for data, error, message in (
        (b'{"schema_version":3,"schema_version":2}', DuplicateKeyError, "duplicate JSON object"),
        (b'{"seconds":NaN}', NonFiniteNumberError, "non-finite JSON number: NaN"),
        (b'{"seconds":-Infinity}', NonFiniteNumberError, "non-finite JSON number: -Infinity"),
        (b'{"nested":{"a":1,"a":1}}', DuplicateKeyError, "duplicate JSON object key: 'a'"),
        (b'{"open":', StrictJSONError, "Expecting value"),
        (b'{"s":"\xff"}', StrictJSONError, "'utf-8' codec can't decode"),
    ):
        path.write_bytes(data)
        with pytest.raises(error, match=message):
            strict_load_bytes(path)
    with pytest.raises(StrictJSONError, match="cannot read"):
        strict_load_bytes(tmp_path / "absent.json")


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ('{"schema_version":3,"target_id":"program","target_id":"other"}', "duplicate JSON"),
        ('{"schema_version":NaN,"target_id":"program"}', "non-finite JSON number: NaN"),
        ('{"schema_version":Infinity}', "non-finite JSON number: Infinity"),
        ('{"schema_version":3,"comparison":{"kind":"literal","kind":"literal"}}', "duplicate"),
        ('{"schema_version":3,', "Expecting"),
    ],
)
def test_load_project_tree_still_gates_each_record_with_the_strict_decoder(
    tmp_path: Path, data: str, message: str
) -> None:
    create_tree(tmp_path)
    (tmp_path / "reprobit/oracles/program.json").write_text(data, encoding="utf-8")
    with pytest.raises(SchemaError, match=f"invalid .*program.json: {message}"):
        load_project_tree(tmp_path)


def test_load_project_tree_reads_array_syntax_into_tuple_fields_without_a_re_dump(
    tmp_path: Path,
) -> None:
    create_tree(tmp_path)
    oracle = tmp_path / "reprobit/oracles/program.json"
    document = strict_loads(oracle.read_bytes())
    assert isinstance(document, dict)
    # Unsorted keys and pretty-printing must be read exactly like canonical bytes.
    oracle.write_text(
        json.dumps(dict(reversed(list(document.items()))), indent=3, sort_keys=False),
        encoding="utf-8",
    )
    bundle = load_project_tree(tmp_path)
    assert bundle.oracle_documents[0] == OracleDocument.model_validate_json(
        canonical_json(document)
    )


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


@pytest.mark.parametrize(
    ("source", "build", "toolchain"),
    (
        (r"R:\Workspace\source", r"R:\workspace\build", r"R:\toolchain"),
        (
            r"R:\Workspace\Project\source",
            r"R:\Workspace\project\build",
            r"R:\toolchain",
        ),
        (
            r"R:\Workspace\source",
            r"R:\Workspace\build",
            r"R:\workspace\toolchain",
        ),
    ),
)
def test_logical_path_profile_rejects_shared_component_case_mismatch(
    source: str,
    build: str,
    toolchain: str,
) -> None:
    with pytest.raises(ValidationError, match="must spell shared DOS path components identically"):
        LogicalPathProfile(source=source, build=build, toolchain=toolchain)


def test_logical_path_profile_preserves_identically_spelled_shared_components() -> None:
    profile = LogicalPathProfile(
        source=r"R:\Workspace\Project\source",
        build=r"R:\Workspace\Project\build",
        toolchain=r"R:\Workspace\toolchain",
    )

    assert profile.source == r"R:\Workspace\Project\source"
    assert profile.build == r"R:\Workspace\Project\build"
    assert profile.toolchain == r"R:\Workspace\toolchain"


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


def test_validate_project_files_cross_validates_an_in_memory_candidate(
    tmp_path: Path,
) -> None:
    create_tree(tmp_path)
    files = {
        PurePosixPath(path.relative_to(tmp_path).as_posix()): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }

    bundle = validate_project_files(files)

    assert bundle.spec.project_id == "sample"
    invalid = dict(files)
    invalid[PurePosixPath("reprobit/oracles/program.json")] = canonical_json(
        {
            "schema_version": 3,
            "target_id": "other",
            "image_size": 10,
            "image_digest": sha(b"reference"),
            "functions": [],
        }
    )
    with pytest.raises(SchemaError, match="oracle target mismatch"):
        validate_project_files(invalid)


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
        "schema_version": 3,
        "toolchain_lock_digest": toolchain_document_digest(baseline.toolchain_lock).model_dump(
            mode="json"
        ),
        "path_profile_id": baseline.spec.paths.id,
        "extractor": "cmake-makefiles-v1",
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
        translation_units=(),
        source_overlay_digest=Digest.from_bytes(b"empty overlay"),
        source_overlay_interventions=(),
        archives=(authority,),
        target_gates=(ClassicTargetGate(target_id="program", build_target="program"),),
    )
    graph = ProducerGraphDocument(
        schema_version=3,
        toolchain_lock_digest=toolchain_document_digest(baseline.toolchain_lock),
        path_profile_id=baseline.spec.paths.id,
        extractor="cmake-makefiles-v1",
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
    assert b'"SourceOverlayIntervention"' not in encoded
    assert b'"source_overlay"' not in encoded
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
        "producer-graph-v3.schema.json": "ProducerGraphDocument",
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
    assert manifest_schema["allOf"][0]["then"]["properties"]["entries"]["minItems"] == 1

    build_plan_description = schemas["build-plan-v3.schema.json"]["description"]
    assert "source_overlay_graph" in build_plan_description
    assert "donor_source_overlay" in build_plan_description
    assert "primary compiler seat" in build_plan_description


def test_incomplete_source_manifest_can_start_empty_but_complete_cannot() -> None:
    incomplete = SourceManifestDocument(
        schema_version=3,
        complete=False,
        entries=(),
    )
    assert incomplete.entries == ()

    with pytest.raises(ValidationError, match="requires at least one entry"):
        SourceManifestDocument(
            schema_version=3,
            complete=True,
            entries=(),
        )
