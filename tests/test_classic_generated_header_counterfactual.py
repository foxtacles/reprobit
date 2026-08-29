from __future__ import annotations

from pathlib import Path
from typing import Literal

from test_classic_semantics import (
    _certified_project_overlay_authority,
    _seat_digest,
)

from reprobit.classic.semantic_contracts import (
    CleanSourceInput,
    ProjectOverlayCompilerEpochPlan,
    ProjectOverlaySourcePair,
)
from reprobit.classic.source_overlay import plan_project_overlay_compiler_epochs
from reprobit.model import Digest
from reprobit.schema import (
    ClassicField,
    ClassicRecipeIntervention,
    SourceManifestEntry,
    source_manifest_digest,
)

_UNIT_PATH = "src/unit.cpp"
_HEADER_PATH = "src/generated.h"
_CARRIER_PATH = "src/carrier.cpp"
_CLEAN_UNIT = b"int value;\n"
_EXISTING_HEADER = b"#define EXISTING_VALUE 1\n"
_GENERATED_HEADER = (
    b"#ifndef GENERATED_RECORDS_H\n"
    b"#define GENERATED_RECORDS_H\n"
    b"enum GeneratedRecord {\n"
    b"\tGeneratedValue\n"
    b"};\n"
    b"#endif\n"
)
_CARRIER = b'#include "generated.h"\n'


def _output(
    path: str,
    effective: bytes,
    operations: list[dict[str, object]],
    *,
    clean: bytes | None = None,
) -> dict[str, object]:
    output: dict[str, object] = {
        "path": path,
        "effective": Digest.from_bytes(effective).value,
        "size": len(effective),
        "ops": operations,
    }
    if clean is not None:
        output["clean"] = Digest.from_bytes(clean).value
    return output


def _include_output() -> tuple[dict[str, object], bytes]:
    fragment = b'#include "generated.h"\n'
    effective = fragment + _CLEAN_UNIT
    return (
        _output(
            _UNIT_PATH,
            effective,
            [
                {
                    "id": "op_include_header",
                    "op": "insert",
                    "anchor": {
                        "ctx": _seat_digest(["<SEAT>", "int", "value", ";"]),
                        "b": 0,
                        "a": 3,
                        "at": "start",
                    },
                    "gen": {
                        "k": "include_seat",
                        "basename": "generated.h",
                        "logical_header": _HEADER_PATH,
                        "style": "quote",
                    },
                }
            ],
            clean=_CLEAN_UNIT,
        ),
        effective,
    )


def _generated_outputs() -> tuple[dict[str, object], dict[str, object]]:
    header = _output(
        _HEADER_PATH,
        _GENERATED_HEADER,
        [
            {
                "id": "op_header_records",
                "op": "append",
                "gen": {
                    "k": "record_header",
                    "logical_path": _HEADER_PATH,
                    "typed_recipe": {
                        "kind": "enum_one_enumerator",
                        "guard": "GENERATED_RECORDS_H",
                        "items": [
                            {
                                "name": "GeneratedRecord",
                                "enumerator": "GeneratedValue",
                            }
                        ],
                    },
                },
            }
        ],
    )
    carrier = _output(
        _CARRIER_PATH,
        _CARRIER,
        [
            {
                "id": "op_carrier_layout",
                "op": "append",
                "gen": {
                    "k": "const_pool",
                    "include_identity": "generated.h",
                    "logical_path": _CARRIER_PATH,
                },
            }
        ],
    )
    return header, carrier


def _with_overlay(
    original: ClassicRecipeIntervention,
    *,
    intervention_id: str,
    outputs: list[dict[str, object]],
    generated_tus: list[str],
) -> ClassicRecipeIntervention:
    values = {item.name: item.value for item in original.parameters}
    values["graph"] = {
        "generated_tus": [
            {
                "path": path,
                "ordinal": index + 2,
                "after": _UNIT_PATH,
            }
            for index, path in enumerate(generated_tus)
        ],
        "link_admissions": [],
    }
    values["outputs"] = sorted(outputs, key=lambda item: str(item["path"]).casefold())
    values["semantic_claims"] = {"schema": 1, "bindings": []}
    return original.model_copy(
        update={
            "id": intervention_id,
            "parameters": tuple(
                ClassicField(name=name, value=value) for name, value in sorted(values.items())
            ),
        }
    )


def _header_plan(
    tmp_path: Path,
    *,
    owner: Literal["same-overlay", "other-overlay", "existing"],
) -> ProjectOverlayCompilerEpochPlan:
    bundle, graph, original, _snapshot = _certified_project_overlay_authority(tmp_path)
    unit_output, effective_unit = _include_output()
    header_output, carrier_output = _generated_outputs()

    overlays: tuple[ClassicRecipeIntervention, ...]
    pairs = [ProjectOverlaySourcePair(_UNIT_PATH, _CLEAN_UNIT, effective_unit)]
    clean_inputs = [CleanSourceInput(_UNIT_PATH, _CLEAN_UNIT)]
    if owner == "same-overlay":
        overlays = (
            _with_overlay(
                original,
                intervention_id="overlay.project",
                outputs=[unit_output, header_output, carrier_output],
                generated_tus=[_CARRIER_PATH],
            ),
        )
    elif owner == "other-overlay":
        overlays = (
            _with_overlay(
                original,
                intervention_id="overlay.project",
                outputs=[unit_output],
                generated_tus=[],
            ),
            _with_overlay(
                original,
                intervention_id="overlay.header-owner",
                outputs=[header_output, carrier_output],
                generated_tus=[_CARRIER_PATH],
            ),
        )
    else:
        overlays = (
            _with_overlay(
                original,
                intervention_id="overlay.project",
                outputs=[unit_output],
                generated_tus=[],
            ),
        )
        assert bundle.source_manifest is not None
        manifest = bundle.source_manifest.model_copy(
            update={
                "entries": (
                    *bundle.source_manifest.entries,
                    SourceManifestEntry(
                        path=_HEADER_PATH,
                        size=len(_EXISTING_HEADER),
                        digest=Digest.from_bytes(_EXISTING_HEADER),
                    ),
                )
            }
        )
        assert bundle.build_plan is not None
        bundle = bundle.model_copy(
            update={
                "source_manifest": manifest,
                "build_plan": bundle.build_plan.model_copy(
                    update={"source_manifest_digest": source_manifest_digest(manifest)}
                ),
            }
        )
        graph = graph.model_copy(
            update={"source_manifest_digest": source_manifest_digest(manifest)}
        )
        clean_inputs.append(CleanSourceInput(_HEADER_PATH, _EXISTING_HEADER))

    if owner != "existing":
        pairs.extend(
            (
                ProjectOverlaySourcePair(_HEADER_PATH, None, _GENERATED_HEADER),
                ProjectOverlaySourcePair(_CARRIER_PATH, None, _CARRIER),
            )
        )

    first_document = bundle.intervention_documents[0].model_copy(update={"interventions": overlays})
    bundle = bundle.model_copy(
        update={
            "intervention_documents": (
                first_document,
                *bundle.intervention_documents[1:],
            ),
        }
    )

    return plan_project_overlay_compiler_epochs(bundle, graph, pairs, clean_inputs)


def test_same_overlay_closed_generated_header_include_joins_counterfactual(
    tmp_path: Path,
) -> None:
    plan = _header_plan(tmp_path, owner="same-overlay")

    assert plan.declaration_outputs[_UNIT_PATH].startswith(b'#include "generated.h"\n')
    assert plan.declaration_leaf_keys["overlay.project"] == (
        ("op_header_records", 0),
        ("op_include_header", 0),
    )
    assert plan.audit_node_ids == frozenset()
    assert plan.runtime_projection_node_ids == frozenset()


def test_existing_header_include_stays_compiler_projected(tmp_path: Path) -> None:
    plan = _header_plan(tmp_path, owner="existing")

    assert plan.declaration_outputs[_UNIT_PATH] == _CLEAN_UNIT
    assert plan.declaration_leaf_keys["overlay.project"] == ()
    assert plan.audit_node_ids == frozenset({"compiler.app.0000"})
    assert plan.runtime_projection_node_ids == frozenset({"compiler.app.0000"})


def test_cross_overlay_generated_header_include_stays_compiler_projected(
    tmp_path: Path,
) -> None:
    plan = _header_plan(tmp_path, owner="other-overlay")

    assert plan.declaration_outputs[_UNIT_PATH] == _CLEAN_UNIT
    assert plan.declaration_leaf_keys["overlay.project"] == ()
    assert plan.declaration_leaf_keys["overlay.header-owner"] == (("op_header_records", 0),)
    assert plan.audit_node_ids == frozenset({"compiler.app.0000"})
    assert plan.runtime_projection_node_ids == frozenset({"compiler.app.0000"})
