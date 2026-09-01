from __future__ import annotations

from typing import Any

import pytest

import reprobit.classic_source_regeneration as source_regeneration
from reprobit.artifacts import digest_bytes
from reprobit.classic import overlay_document
from reprobit.classic_source_regeneration import (
    _ClassicRegenerationContext,
    _render_donor_relocation_batch,
)


class _Reader:
    def read(self, relative: str, *, wanted_by: str) -> bytes:  # pragma: no cover - unused
        raise AssertionError("the batch helper never reads source")


def _context() -> _ClassicRegenerationContext:
    return _ClassicRegenerationContext(
        documents={},
        plan_relative="reprobit/build-plan.json",
        reader=_Reader(),
        error_type=ValueError,
    )


def _item(path: str, *, stale: bool, reloc: bool) -> dict[str, Any]:
    clean = f"clean bytes of {path}".encode()
    operations: list[dict[str, Any]] = [{"op": "append", "gen": {"k": "lines", "n": 1}}]
    if reloc:
        operations.append({"op": "delete", "gen": {"k": "reloc"}})
    return {
        "rendering": {"path": path},
        "path": path,
        "label": f"donor rendering {path!r}",
        "clean_key": "renderings[0].clean_sha256",
        "rendered_key": "renderings[0].rendered_sha256",
        "operations": operations,
        "current": clean,
        "current_digest": digest_bytes(clean),
        "pinned_clean": "stale" if stale else digest_bytes(clean),
        "pinned_rendered": "pinned-rendered",
    }


class _Receipt:
    def __init__(self, path: str) -> None:
        self.path = path
        self.output_digest = f"rendered:{path}"


class _Result:
    def __init__(self, paths: list[str]) -> None:
        self.receipts = [_Receipt(path) for path in paths]


def test_relocation_pair_is_rendered_in_one_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[tuple[str, ...], tuple[str, ...]]] = []

    def fake_render(declarations: Any, clean_inputs: Any, **_: Any) -> _Result:
        paths = tuple(str(item["path"]) for item in declarations)
        calls.append((paths, tuple(sorted(clean_inputs))))
        return _Result([str(item["path"]) for item in declarations])

    monkeypatch.setattr(overlay_document, "render_classic_overlay_proposal", fake_render)
    prepared = [
        _item("include/unit.h", stale=True, reloc=True),
        _item("src/unit.cpp", stale=False, reloc=True),
    ]

    digests = _render_donor_relocation_batch(_context(), prepared, label="donor d0")

    # Both sides go into a single render, including the rendering whose own
    # clean bytes did not change: the relocated bytes come from its partner.
    assert calls == [(("include/unit.h", "src/unit.cpp"), ("include/unit.h", "src/unit.cpp"))]
    assert digests == {
        "include/unit.h": "rendered:include/unit.h",
        "src/unit.cpp": "rendered:src/unit.cpp",
    }


def test_unchanged_relocation_donor_is_not_rendered(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_render(*_: Any, **__: Any) -> _Result:  # pragma: no cover - must not run
        raise AssertionError("nothing is stale, so nothing should be rendered")

    monkeypatch.setattr(overlay_document, "render_classic_overlay_proposal", fail_render)
    prepared = [
        _item("include/unit.h", stale=False, reloc=True),
        _item("src/unit.cpp", stale=False, reloc=True),
    ]

    assert _render_donor_relocation_batch(_context(), prepared, label="donor d0") == {}


def test_donor_without_relocation_keeps_the_single_render_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_render(*_: Any, **__: Any) -> _Result:  # pragma: no cover - must not run
        raise AssertionError("a donor without a relocation renders one file at a time")

    monkeypatch.setattr(overlay_document, "render_classic_overlay_proposal", fail_render)
    prepared = [
        _item("include/unit.h", stale=True, reloc=False),
        _item("src/unit.cpp", stale=True, reloc=False),
    ]

    assert _render_donor_relocation_batch(_context(), prepared, label="donor d0") == {}


def test_batch_render_failure_is_reported_against_the_donor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_render(*_: Any, **__: Any) -> _Result:
        raise ValueError("producer/consumer dependency universe differs")

    monkeypatch.setattr(overlay_document, "render_classic_overlay_proposal", raise_render)
    prepared = [
        _item("include/unit.h", stale=True, reloc=True),
        _item("src/unit.cpp", stale=False, reloc=True),
    ]

    with pytest.raises(ValueError, match="donor d0 cannot be re-rendered"):
        _render_donor_relocation_batch(_context(), prepared, label="donor d0")


def test_single_rendering_donor_never_batches(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_render(*_: Any, **__: Any) -> _Result:  # pragma: no cover - must not run
        raise AssertionError("one rendering cannot form a relocation pair")

    monkeypatch.setattr(overlay_document, "render_classic_overlay_proposal", fail_render)
    prepared = [_item("include/unit.h", stale=True, reloc=True)]

    assert _render_donor_relocation_batch(_context(), prepared, label="donor d0") == {}
    assert source_regeneration._DONOR_OVERLAY_FAMILY == "donor_source_overlay"
