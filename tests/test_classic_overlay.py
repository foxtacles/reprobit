from __future__ import annotations

import json
import os
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path

import pytest

from reprobit.artifacts import digest_bytes
from reprobit.classic_overlay import (
    ClassicOverlayDialect,
    ClassicOverlayRenderSession,
    infer_classic_overlay_dialect,
    render_classic_overlay,
    render_classic_overlay_declarations,
    render_classic_overlay_generator,
    render_classic_overlay_leaf_subset,
    render_classic_overlay_subset,
)
from reprobit.source import SourceEditError


def _seat_digest(tokens: list[str]) -> str:
    return digest_bytes("\0".join(tokens).encode("ascii"))


def _simple_declaration() -> tuple[dict[str, object], dict[str, bytes], bytes]:
    source = b"int value;\n"
    generated = b"class Spare;\n"
    effective = generated + source
    declaration: dict[str, object] = {
        "path": "src/unit.cpp",
        "clean": digest_bytes(source),
        "effective": digest_bytes(effective),
        "size": len(effective),
        "ops": [
            {
                "op": "insert",
                "anchor": {
                    "ctx": _seat_digest(["<SEAT>", "int", "value", ";"]),
                    "b": 0,
                    "a": 3,
                    "at": "start",
                },
                "gen": {"k": "fwd", "id": "Spare"},
            }
        ],
    }
    return declaration, {"src/unit.cpp": source}, effective


def test_render_declarations_returns_fresh_mapping_receipts() -> None:
    declaration, clean, effective = _simple_declaration()

    result = render_classic_overlay_declarations([declaration], clean)

    assert result.outputs == {"src/unit.cpp": effective}
    receipt = result.receipts[0]
    assert receipt.path == "src/unit.cpp"
    assert receipt.input_digest == digest_bytes(clean["src/unit.cpp"])
    assert receipt.output_digest == digest_bytes(effective)
    assert receipt.operations[0].fragment_digest == digest_bytes(b"class Spare;\n")
    assert receipt.operations[0].anchors[0].byte_offset == 0


def test_complete_document_uses_the_same_renderer() -> None:
    declaration, clean, effective = _simple_declaration()
    document = {
        "schema": 2,
        "outputs": [declaration],
        "graph": {"generated_tus": [], "link_admissions": []},
    }

    result = render_classic_overlay(document, clean)

    assert result.outputs["src/unit.cpp"] == effective


def test_operation_subset_is_validated_but_uses_fresh_counterfactual_identity() -> None:
    declaration, clean, effective = _simple_declaration()
    operation = declaration["ops"][0]
    assert isinstance(operation, dict)
    operation["id"] = "op_forward"
    document = {
        "schema": 2,
        "outputs": [declaration],
        "graph": {"generated_tus": [], "link_admissions": []},
    }

    empty = render_classic_overlay_subset(document, clean, frozenset())
    selected = render_classic_overlay_subset(
        document, clean, frozenset({"op_forward"})
    )

    assert empty.outputs == clean
    assert empty.receipts[0].operations == ()
    assert selected.outputs == {"src/unit.cpp": effective}
    assert selected.receipts[0].operations[0].operation_id == "op_forward"


def test_operation_subset_rejects_unknown_or_mutable_selection() -> None:
    declaration, clean, _effective = _simple_declaration()
    document = {
        "schema": 2,
        "outputs": [declaration],
        "graph": {"generated_tus": [], "link_admissions": []},
    }

    with pytest.raises(ValueError, match="frozenset"):
        render_classic_overlay_subset(document, clean, set())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unknown operations"):
        render_classic_overlay_subset(document, clean, frozenset({"op_missing"}))


def test_leaf_subset_preserves_mixed_sequence_canvas() -> None:
    source = b"int value;\n"
    declaration = {
        "path": "src/unit.cpp",
        "clean": digest_bytes(source),
        "effective": digest_bytes(b"class Spare;\n\nint changed;\n" + source),
        "size": len(b"class Spare;\n\nint changed;\n" + source),
        "ops": [
            {
                "id": "op_mixed",
                "op": "insert",
                "anchor": {
                    "ctx": _seat_digest(["<SEAT>", "int", "value", ";"]),
                    "b": 0,
                    "a": 3,
                    "at": "start",
                },
                "gen": {
                    "k": "seq",
                    "lines": 3,
                    "items": [
                        {"k": "fwd", "id": "Spare", "line": 1},
                        {
                            "k": "proto",
                            "id": "changed",
                            "return_type": "int",
                            "parameters": [],
                            "line": 3,
                        },
                    ],
                },
            }
        ],
    }
    # Use a valid semantic second child whose rendered line is easy to distinguish.
    declaration["effective"] = digest_bytes(b"class Spare;\n\nint changed();\n" + source)
    declaration["size"] = len(b"class Spare;\n\nint changed();\n" + source)
    document = {
        "schema": 2,
        "outputs": [declaration],
        "graph": {"generated_tus": [], "link_admissions": []},
    }

    result = render_classic_overlay_leaf_subset(
        document,
        {"src/unit.cpp": source},
        frozenset({("op_mixed", 0)}),
    )

    assert result.outputs["src/unit.cpp"] == b"class Spare;\n\n\n" + source
    assert len(result.receipts[0].operations) == 1


def test_leaf_subset_rejects_unknown_leaf() -> None:
    declaration, clean, _effective = _simple_declaration()
    operation = declaration["ops"][0]
    assert isinstance(operation, dict)
    operation["id"] = "op_forward"
    document = {
        "schema": 2,
        "outputs": [declaration],
        "graph": {"generated_tus": [], "link_admissions": []},
    }

    with pytest.raises(ValueError, match="unknown leaves"):
        render_classic_overlay_leaf_subset(
            document, clean, frozenset({("op_forward", 1)})
        )


def test_render_session_reuses_only_compact_requested_anchor_indexes() -> None:
    declaration, clean, effective = _simple_declaration()
    document = {
        "schema": 2,
        "outputs": [declaration],
        "graph": {"generated_tus": [], "link_admissions": []},
    }

    with ClassicOverlayRenderSession() as session:
        first = render_classic_overlay(document, clean, session=session)
        first_stats = session.stats
        second = render_classic_overlay(document, clean, session=session)
        second_stats = session.stats

    assert first == second
    assert first.outputs["src/unit.cpp"] == effective
    assert first_stats.token_index_builds == 1
    assert first_stats.anchor_batch_builds == 1
    assert first_stats.anchor_windows_hashed == 1
    assert first_stats.retained_index_bytes > 0
    assert first_stats.retained_anchor_requests == 1
    assert second_stats.token_index_builds == 1
    assert second_stats.token_index_hits == 1
    assert second_stats.anchor_batch_builds == 1
    assert second_stats.anchor_batch_hits == 1
    assert second_stats.anchor_windows_hashed == 1


def test_render_session_is_thread_safe_and_closes_deterministically() -> None:
    declaration, clean, effective = _simple_declaration()
    document = {
        "schema": 2,
        "outputs": [declaration],
        "graph": {"generated_tus": [], "link_admissions": []},
    }
    session = ClassicOverlayRenderSession()
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = tuple(
            executor.map(
                lambda _index: render_classic_overlay(
                    document, clean, session=session
                ),
                range(12),
            )
        )
    assert all(result.outputs["src/unit.cpp"] == effective for result in results)
    assert session.stats.token_index_builds == 1
    assert session.stats.anchor_batch_builds == 1
    assert session.stats.anchor_batch_hits == 11

    session.close()
    assert session.stats.retained_token_indexes == 0
    assert session.stats.retained_index_bytes == 0
    assert session.stats.retained_anchor_batches == 0
    assert session.stats.retained_anchor_requests == 0
    with pytest.raises(ValueError, match="session is closed"):
        render_classic_overlay(document, clean, session=session)


def test_anchor_ambiguity_behavior_is_preserved_by_match_only_index() -> None:
    source = b"int value; int value;\n"
    generated = b"class Spare;\n"
    declaration = {
        "path": "src/unit.cpp",
        "clean": digest_bytes(source),
        "effective": digest_bytes(generated + source),
        "size": len(generated + source),
        "ops": [
            {
                "op": "insert",
                "anchor": {
                    "ctx": _seat_digest(["<SEAT>", "int", "value", ";"]),
                    "b": 0,
                    "a": 3,
                    "at": "start",
                },
                "gen": {"k": "fwd", "id": "Spare"},
            }
        ],
    }

    with pytest.raises(SourceEditError, match="ambiguous"):
        render_classic_overlay_declarations(
            [declaration], {"src/unit.cpp": source}
        )


def test_declaration_digest_rejects_changed_clean_input() -> None:
    declaration, _, _ = _simple_declaration()

    with pytest.raises(SourceEditError, match="differs from its pin"):
        render_classic_overlay_declarations([declaration], {"src/unit.cpp": b"int other;\n"})


def test_generator_registry_and_fields_fail_closed() -> None:
    with pytest.raises(SourceEditError, match="unsupported"):
        render_classic_overlay_generator({"k": "free_text", "text": "payload"})
    with pytest.raises(SourceEditError, match="fields differ"):
        render_classic_overlay_generator({"k": "fwd", "id": "Spare", "text": "payload"})


def test_path_casefold_collisions_are_rejected() -> None:
    declaration, clean, _ = _simple_declaration()
    duplicate = dict(declaration)
    duplicate["path"] = "SRC/unit.cpp"
    duplicate["clean"] = digest_bytes(clean["src/unit.cpp"])

    with pytest.raises(SourceEditError, match="casefold collision"):
        render_classic_overlay_declarations(
            [duplicate, declaration],
            {"SRC/unit.cpp": clean["src/unit.cpp"], "src/unit.cpp": clean["src/unit.cpp"]},
        )


def test_legacy_implicit_probe_type_requires_an_explicit_dialect() -> None:
    generator: dict[str, object] = {
        "k": "member_probe",
        "arguments": [{"kind": "integer", "value": 0}],
        "function_identifier": "Probe",
        "inline_depth": 0,
        "qualified_member": ["Bitmap", "Call"],
        "receiver_type": "Bitmap",
    }

    with pytest.raises(SourceEditError, match="ClassicOverlayDialect"):
        render_classic_overlay_generator(generator)
    rendered = render_classic_overlay_generator(
        generator,
        dialect=ClassicOverlayDialect(qualified_member_probe_return_type="long"),
    )
    assert b"long Probe(Bitmap* p_bitmap)" in rendered


def _probe_document() -> dict[str, object]:
    source = b"int marker;\n"
    return {
        "schema": 2,
        "outputs": [
            {
                "path": "src/unit.cpp",
                "clean": digest_bytes(source),
                "effective": "0" * 64,
                "size": 0,
                "ops": [
                    {
                        "op": "insert",
                        "anchor": {
                            "ctx": _seat_digest(["<SEAT>", "int", "marker", ";"]),
                            "b": 0,
                            "a": 3,
                            "at": "start",
                        },
                        "gen": {
                            "k": "member_probe",
                            "arguments": [{"kind": "integer", "value": 0}],
                            "function_identifier": "ProbeCarrier",
                            "inline_depth": 0,
                            "qualified_member": ["Widget", "Probe"],
                            "receiver_type": "Widget",
                        },
                    }
                ],
            }
        ],
        "graph": {"generated_tus": [], "link_admissions": []},
    }


def test_member_probe_dialect_is_inferred_and_locked_from_clean_declarations() -> None:
    document = _probe_document()
    sources = {
        "include/widget.h": b"class Widget { public: virtual int Probe(int); };\n"
    }

    inferred = infer_classic_overlay_dialect(document, sources)

    assert inferred == ClassicOverlayDialect(qualified_member_probe_return_type="int")
    assert infer_classic_overlay_dialect(
        document, sources, locked_dialect=inferred
    ) == inferred
    with pytest.raises(SourceEditError, match="locked classic overlay dialect differs"):
        infer_classic_overlay_dialect(
            document,
            sources,
            locked_dialect=ClassicOverlayDialect(qualified_member_probe_return_type="long"),
        )


def test_member_probe_dialect_inference_rejects_ambiguous_declarations() -> None:
    document = _probe_document()
    sources = {
        "include/first.h": b"class Widget { public: virtual int Probe(int); };\n",
        "include/second.h": b"class Widget { public: virtual long Probe(int); };\n",
    }

    with pytest.raises(SourceEditError, match="return type is ambiguous"):
        infer_classic_overlay_dialect(document, sources)


@pytest.mark.parametrize(
    ("generator", "expected"),
    [
        (
            {
                "k": "dead_updates",
                "id": "state",
                "initial": 0,
                "increment": 1,
                "repeat": 2,
                "nl": False,
            },
            b"{ int state = 0; state = state + 1; state = state + 1; }",
        ),
        (
            {
                "k": "default_ctor_dead_updates",
                "class": "Widget",
                "id": "state",
                "initial": 0,
                "increment": 1,
                "repeat": 1,
            },
            b"\tWidget() { int state = 0; state = state + 1; }\n",
        ),
        (
            {
                "k": "for_init_decl",
                "form": "declaration_in_initializer_v1",
                "type": "Cursor",
                "id": "it",
                "container": "items",
                "begin": "begin",
                "end": "end",
                "declaration_indent": "\t",
            },
            b"\tfor (Cursor it = items.begin(); it != items.end(); it++) {\n",
        ),
        (
            {
                "k": "fixed_array_fill",
                "array": "values",
                "index": "i",
                "index_type": "int",
                "count": 3,
                "value": -1,
                "declaration_indent": "\t",
            },
            b"\tfor (int i = 0; i < 3; i++) values[i] = -1;\n",
        ),
        (
            {
                "k": "fixed_array_shuffle_countdown",
                "array": "values",
                "index": "i",
                "index_type": "int",
                "pointer": "cursor",
                "element_type": "short",
                "swap": "swap",
                "swap_type": "int",
                "temporary": "temporary",
                "temporary_type": "short",
                "random_function": "randomValue",
                "count": 4,
                "declaration_indent": "\t",
            },
            (
                b"\tshort* cursor = values;\n"
                b"\tfor (i = 4; i != 0; i--) {\n"
                b"\t\tcursor++;\n"
                b"\t\tint swap = randomValue() % 4;\n"
                b"\t\tshort temporary = cursor[-1];\n"
                b"\t\tcursor[-1] = values[swap];\n"
                b"\t\tvalues[swap] = temporary;\n"
                b"\t}\n"
            ),
        ),
        (
            {
                "k": "inclusive_extent",
                "type": "int",
                "id": "width",
                "source": {"object": "box", "aggregate_accessor": "bounds"},
                "seed_extent_accessor": "extent",
                "upper_endpoint_accessor": "right",
                "lower_endpoint_accessor": "left",
                "destination": {"object": "surface", "member": "widthValue"},
                "declaration_indent": "\t",
                "barrier": "msvc_i386_empty_inline_assembly_v1",
            },
            (
                b"\tint width = box.bounds().right() - box.bounds().left();\n"
                b"\t++width;\n"
                b"#if defined(_MSC_VER) && defined(_M_IX86)\n"
                b"\t__asm {\n"
                b"\t}\n"
                b"#endif\n"
                b"\tsurface.widthValue = width;\n"
            ),
        ),
        (
            {
                "k": "ctor_alloc_lift",
                "role": "call_site",
                "class_identifier": "Widget",
                "parameter_identifier": "key",
                "buffer_member": "buffer",
                "buffer_cast_type": "char*",
                "element_type": "char",
                "extent_function": "length",
                "copy_function": "copyValue",
                "null_members": ["payload"],
                "caller_result_identifier": "raw",
                "caller_result_type": "char*",
                "null_argument_position": 0,
                "iterator_type": "Cursor",
                "iterator_identifier": "it",
                "container_identifier": "items",
                "find_member": "find",
                "declaration_indent": "\t",
            },
            b"\tCursor it = items.find(Widget(key));\n",
        ),
        (
            {
                "k": "member_sig",
                "class_identifier": "Widget",
                "member_identifier": "Widget",
                "kind": "destructor",
                "form": "qualified_definition_header",
                "nl": False,
            },
            b"Widget::~Widget()",
        ),
        (
            {
                "k": "capture_tail",
                "role": "tail_return",
                "capture": "found",
                "label": "done",
                "declaration_indent": "\t",
            },
            b"\ndone:\n\treturn found;\n",
        ),
    ],
)
def test_donor_generator_registry_exact_fragments(
    generator: dict[str, object], expected: bytes
) -> None:
    assert render_classic_overlay_generator(generator) == expected


def test_authenticated_relocation_requires_one_producer_and_consumer() -> None:
    held = b"{\nreturn;\n}"
    destination = b"int marker;\n"
    pin = {
        "baseline_sha256": digest_bytes(held),
        "baseline_size": len(held),
        "baseline_line_count": held.count(b"\n"),
        "baseline_significant_token_sha256": _seat_digest(["{", "return", ";", "}"]),
    }
    relocation = {
        "k": "reloc",
        "range_identity": "Widget::~Widget",
        "ordinary_owner": "include/widget.h",
        "byte_destination": "src/widget.cpp",
        "source_range_token_pin": pin,
        "transfer": "copy_authenticated_clean_source_range",
        "source_operation_id": "op_move_body",
        "range_dependency_id": "widget_body",
        "range_render_policy": "strip_comments_preserve_physical_lines_v1",
    }
    effective_destination = held + b"\n" + destination
    declarations = [
        {
            "path": "include/widget.h",
            "clean": digest_bytes(held),
            "effective": digest_bytes(b""),
            "ops": [
                {
                    "id": "op_move_body",
                    "op": "delete",
                    "from": {
                        "ctx": _seat_digest(["<SEAT>", "{", "return", ";", "}"]),
                        "b": 0,
                        "a": 4,
                        "at": "start",
                    },
                    "to": {
                        "ctx": _seat_digest(["{", "return", ";", "}", "<SEAT>"]),
                        "b": 4,
                        "a": 0,
                        "at": "end",
                    },
                    "removed": {"sha256": digest_bytes(held), "size": len(held)},
                    "gen": relocation,
                }
            ],
        },
        {
            "path": "src/widget.cpp",
            "clean": digest_bytes(destination),
            "effective": digest_bytes(effective_destination),
            "ops": [
                {
                    "id": "op_receive_body",
                    "op": "insert",
                    "anchor": {
                        "ctx": _seat_digest(["<SEAT>", "int", "marker", ";"]),
                        "b": 0,
                        "a": 3,
                        "at": "start",
                    },
                    "gen": relocation,
                }
            ],
        },
    ]

    result = render_classic_overlay_declarations(
        declarations,
        {"include/widget.h": held, "src/widget.cpp": destination},
    )

    assert result.outputs == {
        "include/widget.h": b"",
        "src/widget.cpp": effective_destination,
    }
    with pytest.raises(SourceEditError, match="dependency universe differs"):
        render_classic_overlay_declarations(
            declarations[:1], {"include/widget.h": held}
        )


def _fixture_environment() -> tuple[Path, Path, ClassicOverlayDialect] | None:
    stage = os.environ.get("REPROBIT_CLASSIC_OVERLAY_STAGE")
    source = os.environ.get("REPROBIT_CLASSIC_OVERLAY_SOURCE")
    return_type = os.environ.get("REPROBIT_CLASSIC_MEMBER_PROBE_RETURN_TYPE")
    if not stage or not source or not return_type:
        return None
    return (
        Path(stage),
        Path(source),
        ClassicOverlayDialect(qualified_member_probe_return_type=return_type),
    )


def _overlay_document(intervention_file: Path) -> Mapping[str, object]:
    shard = json.loads(intervention_file.read_text(encoding="utf-8"))
    interventions = [
        item for item in shard["interventions"] if item["family"] == "source_overlay_graph"
    ]
    assert len(interventions) == 1
    parameters = {item["name"]: item["value"] for item in interventions[0]["parameters"]}
    return {
        "schema": parameters["schema"],
        "outputs": parameters["outputs"],
        "graph": parameters["graph"],
    }


@pytest.mark.skipif(
    _fixture_environment() is None,
    reason="external migrated-overlay regression fixture is not configured",
)
def test_all_migrated_overlay_shards_render_to_their_declared_identities() -> None:
    fixture = _fixture_environment()
    assert fixture is not None
    stage, source_root, dialect = fixture
    shards = sorted((stage / "reprobit" / "interventions").glob("shared-*.json"))
    documents = [_overlay_document(path) for path in shards]
    assert len(documents) == 3

    rendered_count = 0
    operation_count = 0
    for document in documents:
        outputs = document["outputs"]
        assert isinstance(outputs, list)
        clean_inputs = {
            output["path"]: (source_root / output["path"]).read_bytes()
            for output in outputs
            if "clean" in output
        }
        result = render_classic_overlay(document, clean_inputs, dialect=dialect)
        rendered_count += len(result.outputs)
        operation_count += sum(len(receipt.operations) for receipt in result.receipts)
        for output in outputs:
            rendered = result.outputs[output["path"]]
            assert len(rendered) == output["size"]
            assert sha256(rendered).hexdigest() == output["effective"]

    assert rendered_count == 164
    assert operation_count == 418


@pytest.mark.skipif(
    _fixture_environment() is None,
    reason="external migrated-overlay regression fixture is not configured",
)
def test_all_migrated_donor_overlays_render_to_their_declared_identities() -> None:
    fixture = _fixture_environment()
    assert fixture is not None
    stage, source_root, dialect = fixture
    canonical_outputs: dict[str, Mapping[str, object]] = {}
    for shard in sorted((stage / "reprobit" / "interventions").glob("shared-*.json")):
        document = _overlay_document(shard)
        outputs = document["outputs"]
        assert isinstance(outputs, list)
        canonical_outputs.update({output["path"]: output for output in outputs})

    proof_by_intervention: dict[str, Mapping[str, object]] = {}
    for proof_path in sorted((stage / "reprobit" / "proofs" / "tus").glob("*.json")):
        proof_shard = json.loads(proof_path.read_text(encoding="utf-8"))
        proof_by_intervention.update(
            {
                proof["intervention_id"]: proof
                for proof in proof_shard["expected_observations"]
            }
        )

    intervention_count = 0
    rendering_count = 0
    operation_count = 0
    for intervention_path in sorted(
        (stage / "reprobit" / "interventions" / "tus").glob("*.json")
    ):
        shard = json.loads(intervention_path.read_text(encoding="utf-8"))
        for intervention in shard["interventions"]:
            if intervention.get("family") != "donor_source_overlay":
                continue
            parameters = {
                item["name"]: item["value"] for item in intervention["parameters"]
            }
            proof = proof_by_intervention[intervention["id"]]
            expected = proof["expected_values"]
            declarations: list[dict[str, object]] = []
            clean_inputs: dict[str, bytes] = {}
            for index, rendering in enumerate(parameters["renderings"]):
                path = rendering["path"]
                operations = list(rendering["operations"])
                if index == 0 and "canonical_overlay_replay" in parameters:
                    assert parameters["canonical_overlay_replay"] == (
                        "owning_translation_unit_v1"
                    )
                    operations = list(canonical_outputs[path]["ops"]) + operations
                declarations.append(
                    {
                        "path": path,
                        "clean": expected[f"renderings[{index}].clean_sha256"],
                        "effective": expected[f"renderings[{index}].rendered_sha256"],
                        "ops": operations,
                    }
                )
                clean_inputs[path] = (source_root / path).read_bytes()

            result = render_classic_overlay_declarations(
                declarations, clean_inputs, dialect=dialect
            )
            intervention_count += 1
            rendering_count += len(result.outputs)
            operation_count += sum(len(receipt.operations) for receipt in result.receipts)

    assert intervention_count == 45
    assert rendering_count == 181
    assert operation_count == 635


@pytest.mark.skipif(
    _fixture_environment() is None,
    reason="external migrated-overlay regression fixture is not configured",
)
def test_migrated_member_probe_dialect_is_inferred_from_the_clean_tree() -> None:
    fixture = _fixture_environment()
    assert fixture is not None
    stage, source_root, expected_dialect = fixture
    documents = [
        _overlay_document(path)
        for path in sorted((stage / "reprobit" / "interventions").glob("shared-*.json"))
    ]
    probe_documents = [document for document in documents if "member_probe" in json.dumps(document)]
    assert len(probe_documents) == 1
    document = probe_documents[0]

    probes: list[tuple[bytes, bytes]] = []

    def collect(value: object) -> None:
        if isinstance(value, dict):
            if value.get("k") == "member_probe":
                qualified = value["qualified_member"]
                probes.append((qualified[-2].encode(), qualified[-1].encode()))
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    collect(document)
    clean_declarations: dict[str, bytes] = {}
    source_suffixes = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc", ".inl"}
    ignored_parts = {".git", ".venv", "CMakeFiles"}
    for path in source_root.rglob("*"):
        relative = path.relative_to(source_root)
        if (
            not path.is_file()
            or path.suffix.casefold() not in source_suffixes
            or any(part in ignored_parts or part.startswith("build-") for part in relative.parts)
        ):
            continue
        data = path.read_bytes()
        if any(owner in data and member in data for owner, member in probes):
            clean_declarations[relative.as_posix()] = data

    inferred = infer_classic_overlay_dialect(
        document,
        clean_declarations,
        locked_dialect=expected_dialect,
    )

    assert inferred == expected_dialect
