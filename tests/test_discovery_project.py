from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

import reprobit.discovery_project as discovery_project
from reprobit.discovery_contracts import (
    InclusiveRange,
    enumerate_declaration_states,
)
from reprobit.discovery_project import (
    ProjectFileSnapshot,
    ProjectGrindPlan,
    StagedProject,
    load_project_grind_plan,
)
from reprobit.model import ByteRange, Digest, Scope
from reprobit.schema import (
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    InterventionDocument,
    LegacyOracleInstallIntervention,
    OracleInstallRange,
)
from reprobit.strict_json import canonical_json


def _config(**updates: object) -> ProjectGrindPlan:
    values: dict[str, object] = {
        "reference_object": "reference/transform.obj",
        "target": "sample",
        "translation_unit": "transform",
        "symbol": "_transform",
        "classes": InclusiveRange(start=1, stop=4),
        "functions": InclusiveRange(start=10, stop=10),
    }
    values.update(updates)
    return ProjectGrindPlan.model_validate(values)


def test_project_grind_plan_is_deliberately_small_and_project_aware() -> None:
    config = _config()

    assert config.plan.symbols == ("_transform",)
    assert len(enumerate_declaration_states(config.plan)) == 4
    serialized = config.model_dump(mode="json", exclude_none=True)
    assert "plan" not in serialized
    assert "mosaic" not in serialized
    assert "max_cells" not in serialized


def test_project_grind_plan_loader_accepts_a_relative_project_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "sample"
    plan = project / "reprobit" / "discovery.json"
    plan.parent.mkdir(parents=True)
    plan.write_bytes(canonical_json(_config()))
    monkeypatch.chdir(tmp_path)

    path, loaded = load_project_grind_plan(Path("sample"))

    assert path == plan
    assert loaded == _config()


@pytest.mark.parametrize(
    "reference",
    (
        "../reference.obj",
        "reference\\transform.obj",
        "reference/NUL.obj",
        "reference/transform.obj:stream",
        "reference/trailing. ",
    ),
)
def test_project_grind_plan_rejects_nonportable_reference_paths(
    reference: str,
) -> None:
    with pytest.raises((ValidationError, ValueError)):
        _config(reference_object=reference)


def test_project_grind_plan_rejects_unbounded_or_generic_campaign_fields() -> None:
    with pytest.raises(ValidationError, match="1 to 64 legal declaration states"):
        _config(
            classes=InclusiveRange(start=1, stop=10),
            functions=InclusiveRange(start=1, stop=100),
        )
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ProjectGrindPlan.model_validate({**_config().model_dump(), "mosaic": {}})


def test_function_authority_check_covers_classic_and_legacy_actions() -> None:
    scope = Scope(
        target="sample",
        translation_unit="transform",
        function="_transform",
    )
    classic = ClassicRecipeIntervention(
        id="classic.function",
        scope=scope,
        rationale="Existing strict function authority.",
        dependencies=("classic.donor",),
        family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
        role=ClassicRecipeRole.FUNCTION,
        build_target="sample",
        symbol="_transform",
    )
    byte_range = ByteRange(offset=0, length=1)
    legacy = LegacyOracleInstallIntervention.freeze(
        id="legacy.function",
        scope=scope,
        rationale="Existing quarantined function authority.",
        dependencies=("legacy.donor",),
        proof_receipt_digest=Digest.from_bytes(b"proof"),
        preimage_digest=Digest.from_bytes(b"preimage"),
        oracle_body_digest=Digest.from_bytes(b"oracle"),
        oracle_target="sample",
        oracle_address=0,
        ranges=(
            OracleInstallRange(
                preimage_range=byte_range,
                output_range=byte_range,
                oracle_range=byte_range,
            ),
        ),
        byte_count=1,
        maximum_oracle_payload_bytes=1,
    )
    document = InterventionDocument(
        schema_version=3,
        target_id="sample",
        translation_unit_id="transform",
        interventions=(classic, legacy),
    )

    assert discovery_project._function_authority_ids(document, "_transform") == (
        "classic.function",
        "legacy.function",
    )


def test_staged_project_copies_only_sealed_inputs_and_cleans_up(
    tmp_path: Path,
) -> None:
    payload = b"sealed project input\n"
    snapshot = ProjectFileSnapshot(
        relative_path="src/transform.cpp",
        digest=Digest.from_bytes(payload),
        payload=payload,
    )

    with StagedProject(tmp_path, (snapshot,)) as staged:
        assert staged.parent == tmp_path
        assert (staged / "src" / "transform.cpp").read_bytes() == payload
        retained = staged

    assert not retained.exists()
