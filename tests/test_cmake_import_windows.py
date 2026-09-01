from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from reprobit.cli import main
from reprobit.discovery_project_grind import enumerate_project_grind_campaign
from reprobit.model import Digest, Scope
from reprobit.producer_graph import ProducerRole
from reprobit.project_loader import load_project_tree
from reprobit.schema import (
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    InterventionDocument,
    ProofDocument,
)
from reprobit.strict_json import canonical_json
from reprobit.transactions import CASTransaction

ROOT = Path(__file__).parents[1]
GRIND_SAMPLE = ROOT / "examples/grind-progress"
_MAX_FAILURE_LOG_BYTES = 64 * 1024


def _retained_failure_logs(project: Path) -> str:
    runs = project / ".reprobit-state" / "runs"
    if not runs.is_dir():
        return "no retained ReproBit run logs were found"
    paths = tuple(
        path
        for path in sorted(runs.rglob("*.log"), key=lambda item: item.as_posix())
        if path.is_file() and not path.is_symlink()
    )
    if not paths:
        return "no retained ReproBit run logs were found"

    diagnostic_root_value = os.environ.get("REPROBIT_NATIVE_LOG_DIR")
    diagnostic_root = Path(diagnostic_root_value) if diagnostic_root_value else None
    if diagnostic_root is not None:
        diagnostic_root.mkdir(parents=True, exist_ok=True)

    excerpts: list[str] = []
    for index, path in enumerate(paths, start=1):
        payload = path.read_bytes()
        if diagnostic_root is not None:
            shutil.copyfile(
                path,
                diagnostic_root / f"retained-{index:02d}-{path.name}",
            )
        relative = path.relative_to(project).as_posix()
        truncated = len(payload) > _MAX_FAILURE_LOG_BYTES
        excerpt = payload[-_MAX_FAILURE_LOG_BYTES:].decode("utf-8", errors="replace")
        prefix = "[earlier bytes omitted]\n" if truncated else ""
        excerpts.append(f"--- {relative} ---\n{prefix}{excerpt}")
    return "\n".join(excerpts)


def _require_cli_success(project: Path, argv: list[str]) -> None:
    exit_code = main(argv)
    if exit_code != 0:
        pytest.fail(
            f"ReproBit CLI exited with {exit_code}: {argv!r}\n{_retained_failure_logs(project)}",
            pytrace=False,
        )


def _seed_timestamp_normalization(project: Path) -> None:
    intervention_path = project / "reprobit/interventions/program.json"
    proof_path = project / "reprobit/proofs/program.json"
    intervention_document = InterventionDocument.model_validate_json(intervention_path.read_bytes())
    proof_document = ProofDocument.model_validate_json(proof_path.read_bytes())
    intervention = ClassicRecipeIntervention(
        id="project.metadata",
        scope=Scope(target="program"),
        rationale="Normalize candidate-owned linker timestamps for repeatable verification.",
        family=ClassicRecipeFamily.IMAGE_METADATA,
        role=ClassicRecipeRole.PROJECT,
        build_target="grind_progress",
        parameters=(
            ClassicField(name="link_time", value=0),
            ClassicField(name="resource_time", value=0),
        ),
    )
    receipt = ClassicProofReceipt(
        id="proof.project.metadata",
        intervention_id=intervention.id,
        family=intervention.family,
    )
    updated_interventions = intervention_document.model_copy(
        update={"interventions": (intervention,)}
    )
    updated_proofs = proof_document.model_copy(update={"expected_observations": (receipt,)})
    transaction = CASTransaction(project)
    transaction.write(
        intervention_path.relative_to(project),
        canonical_json(updated_interventions),
        expected_sha256=Digest.from_path(intervention_path).value,
    )
    transaction.write(
        proof_path.relative_to(project),
        canonical_json(updated_proofs),
        expected_sha256=Digest.from_path(proof_path).value,
    )
    transaction.commit()


@pytest.mark.skipif(os.name != "nt", reason="native NMake import requires Windows")
@pytest.mark.msvc42
def test_fresh_project_imports_builds_grinds_and_verifies_with_nmake(
    tmp_path: Path,
) -> None:
    toolchain_value = os.environ.get("REPROBIT_MSVC_4_2_ROOT")
    if toolchain_value is None:
        pytest.skip("REPROBIT_MSVC_4_2_ROOT is not configured")
    toolchain = Path(toolchain_value).resolve(strict=True)
    project = tmp_path / "project"

    _require_cli_success(
        project,
        [
            "init",
            str(project),
            "--target",
            "program",
            "--artifact",
            "build/grind-progress.exe",
            "--oracle",
            "reference/grind-progress.exe",
        ],
    )
    shutil.copyfile(GRIND_SAMPLE / "transform_one.cpp", project / "transform_one.cpp")
    shutil.copyfile(GRIND_SAMPLE / "transform_two.cpp", project / "transform_two.cpp")
    shutil.copyfile(GRIND_SAMPLE / "prepare_reference.py", project / "prepare_reference.py")
    shutil.copyfile(GRIND_SAMPLE / "CMakeLists.txt", project / "CMakeLists.txt")
    _require_cli_success(
        project,
        [
            "setup",
            str(project),
            "--toolchain-root",
            str(toolchain),
            "--no-save",
            "--skip-probe",
        ],
    )
    _require_cli_success(
        project,
        [
            "source",
            "lock",
            str(project),
            "--path",
            "reprobit.toml",
            "--path",
            "CMakeLists.txt",
            "--path",
            "transform_one.cpp",
            "--path",
            "transform_two.cpp",
        ],
    )
    prepared = subprocess.run(
        (
            sys.executable,
            project / "prepare_reference.py",
            "--toolchain-root",
            toolchain,
        ),
        cwd=project,
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert prepared.returncode == 0, prepared.stdout + prepared.stderr
    assert (project / "reference/grind-progress.exe").is_file()
    assert (project / "reference/transform_one.obj").is_file()
    assert (project / "reference/transform_two.obj").is_file()

    _require_cli_success(
        project,
        [
            "import",
            "cmake",
            str(project),
            "--target",
            "program=grind_progress",
            "--toolchain-root",
            str(toolchain),
            "--keep-workspace",
            "always",
        ],
    )

    bundle = load_project_tree(project)
    assert bundle.producer_graph is not None
    assert bundle.build_plan is not None
    assert len(bundle.build_plan.translation_units) == 2
    assert {unit.source for unit in bundle.build_plan.translation_units} == {
        "transform_one.cpp",
        "transform_two.cpp",
    }
    configure_logs = tuple(
        (project / ".reprobit-state/runs").glob("import-*/cmake/build/configure.log")
    )
    assert len(configure_logs) == 1
    assert "The CXX compiler identification is MSVC 10.20" in configure_logs[0].read_text(
        encoding="utf-8"
    )
    compilers = tuple(
        node for node in bundle.producer_graph.nodes if node.role is ProducerRole.COMPILER
    )
    assert len(compilers) == 2
    assert all(
        {"/zi", "/o2", "/ob1"} <= {argument.casefold() for argument in compiler.arguments}
        for compiler in compilers
    )
    for unit in bundle.build_plan.translation_units:
        assert (project / "reprobit/interventions" / f"{unit.id}.json").is_file()
        assert (project / "reprobit/proofs" / f"{unit.id}.json").is_file()
    assert enumerate_project_grind_campaign(project).eligible_units == 2
    _seed_timestamp_normalization(project)

    _require_cli_success(
        project,
        [
            "build",
            str(project),
            "--toolchain-root",
            str(toolchain),
        ],
    )
    _require_cli_success(
        project,
        [
            "discover",
            "grind",
            str(project),
            "--accept-progress",
            "--toolchain-root",
            str(toolchain),
        ],
    )
    accepted = load_project_tree(project)
    functions = tuple(
        item
        for item in accepted.interventions
        if isinstance(item, ClassicRecipeIntervention) and item.role is ClassicRecipeRole.FUNCTION
    )
    assert {item.symbol for item in functions} == {"_transform_one", "_transform_two"}
    _require_cli_success(
        project,
        [
            "verify",
            str(project),
            "--toolchain-root",
            str(toolchain),
        ],
    )
