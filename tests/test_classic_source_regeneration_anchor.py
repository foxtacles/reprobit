from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from reprobit.artifacts import digest_bytes
from reprobit.classic.overlay_document import render_classic_overlay_proposal
from reprobit.classic_source_regeneration import (
    _ClassicRegenerationContext,
    _legacy_identity,
    _parameter_map,
    _refresh_donor_overlays,
    _refresh_source_overlays,
)
from reprobit.source_regeneration import ProjectSourceReader

_PATH = "src/unit.cpp"
_ORIGINAL = b"int alpha;\nint omega;\n"
_EDITED = b"int alpha;\nint beta;\nint omega;\n"


def _seat_digest(tokens: list[str]) -> str:
    return digest_bytes("\0".join(tokens).encode("ascii"))


def _operation() -> dict[str, Any]:
    return {
        "id": "op_spare",
        "op": "insert",
        "anchor": {
            "ctx": _seat_digest(["int", "alpha", ";", "<SEAT>", "int", "omega", ";"]),
            "b": 3,
            "a": 3,
            "at": "before_token",
        },
        "gen": {"k": "fwd", "id": "Spare"},
    }


def _output() -> dict[str, Any]:
    operations = [_operation()]
    declaration = {
        "path": _PATH,
        "clean": digest_bytes(_ORIGINAL),
        "effective": "0" * 64,
        "ops": operations,
    }
    rendered = render_classic_overlay_proposal([declaration], {_PATH: _ORIGINAL}).outputs[_PATH]
    return {
        "path": _PATH,
        "clean": digest_bytes(_ORIGINAL),
        "effective": digest_bytes(rendered),
        "size": len(rendered),
        "ops": operations,
    }


def _context(
    root: Path,
    output: dict[str, Any],
    *,
    clean_preimage_root: Path | None = None,
) -> _ClassicRegenerationContext:
    overlay = {
        "family": "source_overlay_graph",
        "parameters": [{"name": "outputs", "value": [output]}],
    }
    return _ClassicRegenerationContext(
        documents={"overlay.json": {"interventions": [overlay]}},
        plan_relative="reprobit/build-plan.json",
        reader=ProjectSourceReader(root, clean_preimage_root=clean_preimage_root),
        error_type=ValueError,
    )


def _donor_context(
    root: Path,
    *,
    pinned_source: bytes,
) -> tuple[
    _ClassicRegenerationContext,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    operations = [_operation()]
    rendering = {"path": _PATH, "operations": operations}
    declaration = {
        "path": _PATH,
        "clean": digest_bytes(pinned_source),
        "effective": "0" * 64,
        "ops": operations,
    }
    pinned_rendered = (
        render_classic_overlay_proposal([declaration], {_PATH: pinned_source})
        .receipts[0]
        .output_digest
    )
    pinned_clean = digest_bytes(pinned_source)
    donor = {
        "id": "donor",
        "family": "donor_source_overlay",
        "parameters": [
            {"name": "renderings", "value": [rendering]},
            {
                "name": "rendering_identity_sha256",
                "value": _legacy_identity(
                    [
                        {
                            **rendering,
                            "clean_sha256": pinned_clean,
                            "rendered_sha256": pinned_rendered,
                        }
                    ]
                ),
            },
        ],
    }
    observation = {
        "expected_values": {
            "renderings[0].clean_sha256": pinned_clean,
            "renderings[0].rendered_sha256": pinned_rendered,
        }
    }
    context = _ClassicRegenerationContext(
        documents={"donor.json": {"interventions": [donor]}},
        plan_relative="reprobit/build-plan.json",
        reader=ProjectSourceReader(root),
        error_type=ValueError,
    )
    context.receipts_by_intervention["donor"] = [("proof.donor", observation)]
    return context, donor, rendering, observation


def _commit(root: Path) -> None:
    subprocess.run(("git", "init", "-q"), cwd=root, check=True)
    subprocess.run(("git", "add", _PATH), cwd=root, check=True)
    subprocess.run(
        (
            "git",
            "-c",
            "user.name=ReproBit tests",
            "-c",
            "user.email=reprobit@example.invalid",
            "commit",
            "-qm",
            "clean source",
        ),
        cwd=root,
        check=True,
    )


def test_source_regeneration_rewitnesses_a_token_seat_from_git_head(tmp_path: Path) -> None:
    source = tmp_path / _PATH
    source.parent.mkdir()
    source.write_bytes(_ORIGINAL)
    _commit(tmp_path)
    source.write_bytes(_EDITED)
    output = _output()
    old_context = output["ops"][0]["anchor"]["ctx"]

    context = _context(tmp_path, output)
    _refresh_source_overlays(context)

    assert output["clean"] == digest_bytes(_EDITED)
    assert output["ops"][0]["anchor"]["ctx"] != old_context
    rendered = render_classic_overlay_proposal([output], {_PATH: _EDITED}).outputs[_PATH]
    assert digest_bytes(rendered) == output["effective"]
    assert rendered.index(b"int beta;") < rendered.index(b"class Spare;")
    assert rendered.index(b"class Spare;") < rendered.index(b"int omega;")


def test_source_regeneration_reads_history_from_the_unstaged_project(tmp_path: Path) -> None:
    original_root = tmp_path / "original"
    original_source = original_root / _PATH
    original_source.parent.mkdir(parents=True)
    original_source.write_bytes(_ORIGINAL)
    _commit(original_root)
    original_source.write_bytes(_EDITED)

    staged_root = tmp_path / "staged"
    staged_source = staged_root / _PATH
    staged_source.parent.mkdir(parents=True)
    staged_source.write_bytes(_EDITED)
    output = _output()

    _refresh_source_overlays(_context(staged_root, output, clean_preimage_root=original_root))

    assert output["clean"] == digest_bytes(_EDITED)
    rendered = render_classic_overlay_proposal([output], {_PATH: _EDITED}).outputs[_PATH]
    assert rendered.index(b"int beta;") < rendered.index(b"class Spare;")
    assert rendered.index(b"class Spare;") < rendered.index(b"int omega;")


def test_donor_private_overlay_rewitnesses_a_token_seat_from_git_head(
    tmp_path: Path,
) -> None:
    source = tmp_path / _PATH
    source.parent.mkdir()
    source.write_bytes(_ORIGINAL)
    _commit(tmp_path)
    source.write_bytes(_EDITED)
    context, donor, rendering, observation = _donor_context(tmp_path, pinned_source=_ORIGINAL)
    old_context = rendering["operations"][0]["anchor"]["ctx"]

    _refresh_donor_overlays(context)

    assert rendering["operations"][0]["anchor"]["ctx"] != old_context
    expected = observation["expected_values"]
    assert expected["renderings[0].clean_sha256"] == digest_bytes(_EDITED)
    declaration = {
        "path": _PATH,
        "clean": digest_bytes(_EDITED),
        "effective": expected["renderings[0].rendered_sha256"],
        "ops": rendering["operations"],
    }
    rendered = render_classic_overlay_proposal([declaration], {_PATH: _EDITED}).outputs[_PATH]
    assert rendered.index(b"int beta;") < rendered.index(b"class Spare;")
    assert rendered.index(b"class Spare;") < rendered.index(b"int omega;")
    assert _parameter_map(donor)["rendering_identity_sha256"] == _legacy_identity(
        [
            {
                **rendering,
                "clean_sha256": digest_bytes(_EDITED),
                "rendered_sha256": expected["renderings[0].rendered_sha256"],
            }
        ]
    )
    assert any("operation op_spare anchor.ctx" in change.location for change in context.changes)


@pytest.mark.parametrize(
    "committed",
    [
        None,
        b"int omega;\nint alpha;\nint omega;\n",
    ],
    ids=["missing-preimage", "ambiguous-one-sided-window"],
)
def test_donor_private_overlay_refuses_an_unproven_token_seat_without_changes(
    tmp_path: Path,
    committed: bytes | None,
) -> None:
    source = tmp_path / _PATH
    source.parent.mkdir()
    pinned_source = committed or _ORIGINAL
    source.write_bytes(pinned_source)
    if committed is not None:
        _commit(tmp_path)
    source.write_bytes(_EDITED)
    context, donor, rendering, observation = _donor_context(tmp_path, pinned_source=pinned_source)
    old_operations = rendering["operations"]
    old_expected = dict(observation["expected_values"])
    old_identity = _parameter_map(donor)["rendering_identity_sha256"]

    with pytest.raises(ValueError, match="cannot be re-rendered"):
        _refresh_donor_overlays(context)

    assert rendering["operations"] is old_operations
    assert observation["expected_values"] == old_expected
    assert _parameter_map(donor)["rendering_identity_sha256"] == old_identity
    assert context.changes == []


@pytest.mark.parametrize("head", [None, b"int sigma;\nint omega;\n"], ids=["missing", "mismatch"])
def test_source_regeneration_refuses_an_unproven_token_seat(
    tmp_path: Path, head: bytes | None
) -> None:
    source = tmp_path / _PATH
    source.parent.mkdir()
    source.write_bytes(head if head is not None else _EDITED)
    if head is not None:
        _commit(tmp_path)
    source.write_bytes(_EDITED)

    with pytest.raises(ValueError, match="cannot be re-rendered"):
        _refresh_source_overlays(_context(tmp_path, _output()))
