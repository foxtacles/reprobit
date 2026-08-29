from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

from reprobit.discovery_contracts import declaration_state_id, enumerate_declaration_states
from reprobit.msvc_discovery import MsvcDiscoveryRequest

ROOT = Path(__file__).parents[1]
EXAMPLES = ROOT / "examples"
DISCOVERY = EXAMPLES / "declaration-discovery"


def _load_script(name: str) -> ModuleType:
    path = DISCOVERY / name
    spec = importlib.util.spec_from_file_location(f"reprobit_example_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_declaration_discovery_requests_are_valid_and_extend_by_one_cell() -> None:
    base = MsvcDiscoveryRequest.model_validate_json((DISCOVERY / "campaign.json").read_bytes())
    extended = MsvcDiscoveryRequest.model_validate_json(
        (DISCOVERY / "campaign-extended.json").read_bytes()
    )

    base_states = enumerate_declaration_states(base.plan)
    extended_states = enumerate_declaration_states(extended.plan)
    assert len(base_states) == 4
    assert len(extended_states) == 5
    assert tuple(map(declaration_state_id, extended_states[:4])) == tuple(
        map(declaration_state_id, base_states)
    )
    assert base.source == extended.source == "transform.cpp"
    assert base.references == extended.references
    assert base.compiler_arguments == extended.compiler_arguments
    assert (DISCOVERY / base.source).is_file()


def test_example_helpers_have_working_help_and_review_only_output() -> None:
    for script in ("prepare_reference.py", "review_report.py"):
        result = subprocess.run(
            (sys.executable, DISCOVERY / script, "--help"),
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert "usage:" in result.stdout

    review = _load_script("review_report.py")
    report = SimpleNamespace(
        cells_total=4,
        cells_built=0,
        cells_cached=4,
        proposals=(
            SimpleNamespace(
                kind=SimpleNamespace(value="whole_body"),
                symbol="_transform",
                finding_id="finding.example",
                rationale="The selected compiler state matches the sealed reference body.",
                state_ids=("state.example",),
                artifact_ids=("artifact.example",),
            ),
        ),
        selected_states=(
            SimpleNamespace(
                state_id="state.example",
                generated_declarations="class EntropyShape0 { void Slot0(); };\n",
            ),
        ),
        artifacts=(
            SimpleNamespace(
                artifact_id="artifact.example",
                role=SimpleNamespace(value="state_carrier"),
                logical_path=".sample-state/cache/artifacts/example.obj",
            ),
        ),
    )

    rendered = review.render_report(report)
    assert rendered.startswith("NON-CERTIFYING DISCOVERY REVIEW")
    assert "0 built; 4 reused" in rendered
    assert "class EntropyShape0" in rendered
    assert "not certified authority" in rendered


def test_examples_keep_generated_outputs_out_and_use_sample_language() -> None:
    assert not tuple(EXAMPLES.rglob("*.obj"))
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "/examples/declaration-discovery/reference.obj" in ignore
    assert "/examples/declaration-discovery/.sample-state/" in ignore
    for path in EXAMPLES.rglob("*"):
        if path.suffix not in {".md", ".py"}:
            continue
        assert re.search(r"\btoy\b", path.read_text(encoding="utf-8"), re.I) is None
