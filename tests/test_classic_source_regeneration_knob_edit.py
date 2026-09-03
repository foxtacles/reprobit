"""Regeneration notices operation-only overlay edits whose clean bytes are unchanged."""

from __future__ import annotations

from typing import Any

from reprobit.artifacts import digest_bytes
from reprobit.classic.overlay_document import render_classic_overlay_proposal
from reprobit.classic_source_regeneration import (
    _ClassicRegenerationContext,
    _legacy_identity,
    _parameter_map,
    _refresh_donor_overlays,
    _refresh_source_overlays,
)

PATH = "src/unit.cpp"
SOURCE = b"int value;\n"
CLEAN = digest_bytes(SOURCE)


class _Reader:
    def __init__(self, files: dict[str, bytes]) -> None:
        self._files = files

    def read(self, relative: str, *, wanted_by: str) -> bytes:
        return self._files[relative]


def _seat(tokens: list[str]) -> str:
    return digest_bytes("\0".join(tokens).encode("ascii"))


def _forward_op(identifier: str) -> dict[str, Any]:
    return {
        "id": "op_forward",
        "op": "insert",
        "anchor": {"ctx": _seat(["<SEAT>", "int", "value", ";"]), "b": 0, "a": 3, "at": "start"},
        "gen": {"k": "fwd", "id": identifier},
    }


def _rendered(ops: list[dict[str, Any]]) -> str:
    declaration = {"path": PATH, "clean": CLEAN, "effective": "0" * 64, "ops": ops}
    result = render_classic_overlay_proposal([declaration], {PATH: SOURCE})
    return result.receipts[0].output_digest


def _rendered_size(ops: list[dict[str, Any]]) -> int:
    declaration = {"path": PATH, "clean": CLEAN, "effective": "0" * 64, "ops": ops}
    result = render_classic_overlay_proposal([declaration], {PATH: SOURCE})
    return result.receipts[0].output_size


def _output(ops: list[dict[str, Any]], effective: str, size: int) -> dict[str, Any]:
    return {"path": PATH, "clean": CLEAN, "size": size, "effective": effective, "ops": ops}


def _overlay(output: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "overlay",
        "family": "source_overlay_graph",
        "parameters": [{"name": "outputs", "value": [output]}],
    }


def _context(documents: dict[str, Any]) -> _ClassicRegenerationContext:
    return _ClassicRegenerationContext(
        documents=documents,
        plan_relative="reprobit/build-plan.json",
        reader=_Reader({PATH: SOURCE}),
        error_type=ValueError,
    )


def test_a_retuned_operation_refreshes_the_effective_pin_without_a_clean_change() -> None:
    stale = _rendered([_forward_op("Spare")])
    stale_size = _rendered_size([_forward_op("Spare")])
    output = _output([_forward_op("Retuned")], stale, stale_size)
    context = _context({"tu.json": {"interventions": [_overlay(output)]}})

    _refresh_source_overlays(context)

    fresh = _rendered([_forward_op("Retuned")])
    fresh_size = _rendered_size([_forward_op("Retuned")])
    assert fresh != stale
    assert output["effective"] == fresh
    assert output["size"] == fresh_size
    assert output["clean"] == CLEAN
    assert context.stale_paths == {PATH: CLEAN}
    assert context.effective_bytes_by_path[PATH] == b"class Retuned;\n" + SOURCE
    assert [(change.location, change.before, change.after) for change in context.changes] == [
        (f"overlay output {PATH!r} effective", stale, fresh),
        (f"overlay output {PATH!r} size", str(stale_size), str(fresh_size)),
    ]


def test_an_unchanged_overlay_is_left_alone() -> None:
    pinned = _rendered([_forward_op("Spare")])
    output = _output([_forward_op("Spare")], pinned, _rendered_size([_forward_op("Spare")]))
    context = _context({"tu.json": {"interventions": [_overlay(output)]}})

    _refresh_source_overlays(context)

    assert output["effective"] == pinned
    assert context.stale_paths == {}
    assert context.changes == []
    assert context.effective_by_path == {PATH: pinned}


def test_a_donor_replaying_the_retuned_overlay_refreshes_its_rendering_pins() -> None:
    stale = _rendered([_forward_op("Spare")])
    output = _output([_forward_op("Retuned")], stale, _rendered_size([_forward_op("Spare")]))
    rendering = {"path": PATH, "operations": []}
    stale_identity = _legacy_identity(
        {
            "renderings": [
                {**rendering, "clean_sha256": CLEAN, "rendered_sha256": stale},
            ],
            "canonical_overlay_replay": "owning_translation_unit_v1",
        }
    )
    donor = {
        "id": "donor",
        "family": "donor_source_overlay",
        "parameters": [
            {"name": "renderings", "value": [rendering]},
            {"name": "canonical_overlay_replay", "value": "owning_translation_unit_v1"},
            {"name": "rendering_identity_sha256", "value": stale_identity},
        ],
    }
    observation = {
        "expected_values": {
            "renderings[0].clean_sha256": CLEAN,
            "renderings[0].rendered_sha256": stale,
        }
    }
    context = _context({"tu.json": {"interventions": [_overlay(output), donor]}})
    context.receipts_by_intervention["donor"] = [("proof.donor", observation)]

    _refresh_source_overlays(context)
    _refresh_donor_overlays(context)

    fresh = _rendered([_forward_op("Retuned")])
    expected = observation["expected_values"]
    assert expected["renderings[0].clean_sha256"] == CLEAN
    assert expected["renderings[0].rendered_sha256"] == fresh
    identity = _parameter_map(donor)["rendering_identity_sha256"]
    assert identity != stale_identity
    assert identity == _legacy_identity(
        {
            "renderings": [
                {**rendering, "clean_sha256": CLEAN, "rendered_sha256": fresh},
            ],
            "canonical_overlay_replay": "owning_translation_unit_v1",
        }
    )
    locations = [change.location for change in context.changes]
    assert "donor renderings[0].rendered_sha256" in locations
    assert "donor rendering_identity_sha256" in locations
    assert "donor renderings[0].clean_sha256" not in locations
