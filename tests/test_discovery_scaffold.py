from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from reprobit.cli import main
from reprobit.discovery_contracts import (
    DeclarationFamily,
    DeclarationShapeSearch,
    enumerate_declaration_states,
)
from reprobit.discovery_scaffold import scaffold_msvc_discovery_request
from reprobit.msvc_discovery import MsvcDiscoveryRequest
from reprobit.strict_json import canonical_json, strict_loads


def _scaffold(**overrides: object) -> bytes:
    values: dict[str, object] = {
        "source": "src/widget.cpp",
        "target": "widget",
        "translation_unit": "widget.main",
        "references": (("?Transform@Widget@@QAEHH@Z", "reference/widget.obj"),),
    }
    values.update(overrides)
    return scaffold_msvc_discovery_request(**values)  # type: ignore[arg-type]


def test_scaffold_emits_a_canonical_bounded_default_request() -> None:
    payload = _scaffold()
    request = MsvcDiscoveryRequest.model_validate_json(payload)

    assert payload == canonical_json(strict_loads(payload))
    assert request.compiler_arguments == ("/nologo", "/O2", "/Ob1", "/Gy", "/Z7")
    assert request.plan.max_cells == 4
    assert len(enumerate_declaration_states(request.plan)) == 4
    assert request.plan.mosaic.max_donors == 2
    assert request.plan.mosaic.max_ranges == 4
    assert request.plan.mosaic.max_candidates_per_symbol == 32
    search = request.plan.searches[0]
    assert isinstance(search, DeclarationShapeSearch)
    assert search.family is DeclarationFamily.DECLARATION_SHAPE
    assert search.classes.start == 1 and search.classes.stop == 4
    assert search.functions.start == search.functions.stop == 10


def test_scaffold_canonicalizes_human_reference_order() -> None:
    references = (
        ("?Zeta@@YAHXZ", "reference/shared.obj"),
        ("?Alpha@@YAHXZ", "reference/shared.obj"),
    )

    first = _scaffold(references=references)
    second = _scaffold(references=tuple(reversed(references)))
    request = MsvcDiscoveryRequest.model_validate_json(first)

    assert first == second
    assert request.plan.symbols == ("?Alpha@@YAHXZ", "?Zeta@@YAHXZ")
    assert tuple(item.symbol for item in request.references) == request.plan.symbols


@pytest.mark.parametrize(
    ("overrides", "message"),
    (
        ({"references": ()}, "at least one symbol"),
        (
            {
                "references": (
                    ("?Transform@@YAHXZ", "reference/a.obj"),
                    ("?Transform@@YAHXZ", "reference/b.obj"),
                )
            },
            "symbol is repeated",
        ),
        (
            {
                "references": (
                    ("?Transform@@YAHXZ", "reference/a.obj"),
                    ("?transform@@YAHXZ", "reference/b.obj"),
                )
            },
            "symbols collide",
        ),
        ({"source": "../widget.cpp"}, "canonical POSIX relative path"),
        (
            {"references": (("?Transform@@YAHXZ", "/reference.obj"),)},
            "canonical POSIX relative path",
        ),
        (
            {"references": (("?Transform@@YAHXZ", "SRC/Widget.cpp"),)},
            "collide under case-insensitive path rules",
        ),
        (
            {"references": (("?Transform@@YAHXZ", "src/widget.cpp/object.obj"),)},
            "overlap as a file and descendant",
        ),
    ),
)
def test_scaffold_refuses_ambiguous_or_unsafe_inputs(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _scaffold(**overrides)


def test_scaffold_accepts_only_existing_safe_compiler_switch_vocabulary() -> None:
    request = MsvcDiscoveryRequest.model_validate_json(
        _scaffold(compiler_arguments=("/nologo", "/Od", "/Gy", "/Z7"))
    )
    assert request.compiler_arguments == ("/nologo", "/Od", "/Gy", "/Z7")

    with pytest.raises(ValidationError, match="path-free code-generation"):
        _scaffold(compiler_arguments=("/Fa../../outside.asm",))


def test_scaffold_is_pure_and_does_not_touch_input_paths(tmp_path: Path) -> None:
    before = tuple(tmp_path.iterdir())
    payload = _scaffold(
        source="missing/source.cpp",
        references=(("?Transform@@YAHXZ", "missing/reference.obj"),),
    )

    assert MsvcDiscoveryRequest.model_validate_json(payload).source == "missing/source.cpp"
    assert tuple(tmp_path.iterdir()) == before


def test_cli_creates_a_ready_to_run_request_without_compiling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)

    assert (
        main(
            [
                "discover",
                "init",
                "--source",
                "src/widget.cpp",
                "--reference",
                "?Transform@Widget@@QAEHH@Z=reference/widget.obj",
            ]
        )
        == 0
    )

    request_path = tmp_path / "discovery-request.json"
    request = MsvcDiscoveryRequest.model_validate_json(request_path.read_bytes())
    assert request.plan.translation_unit == "widget"
    assert request.plan.max_cells == 4
    rendered = capsys.readouterr().out
    assert "Nothing was compiled or applied" in rendered
    assert "Next: rbit discover discovery-request.json" in rendered


def test_cli_scaffold_refuses_to_overwrite_a_campaign_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)

    assert (
        main(
            [
                "discover",
                "init",
                "--source",
                "request.json",
                "--reference",
                "symbol=reference.obj",
                "--request-file",
                "REQUEST.JSON",
            ]
        )
        == 2
    )
    assert "must not overlap" in capsys.readouterr().err
