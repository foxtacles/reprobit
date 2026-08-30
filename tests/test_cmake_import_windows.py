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
GRIND_SAMPLE = ROOT / "examples/grind"


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
        build_target="grind",
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
def test_fresh_project_imports_builds_grinds_and_verifies_with_nmake(
    tmp_path: Path,
) -> None:
    toolchain_value = os.environ.get("REPROBIT_MSVC_4_2_ROOT")
    if toolchain_value is None:
        pytest.skip("REPROBIT_MSVC_4_2_ROOT is not configured")
    toolchain = Path(toolchain_value).resolve(strict=True)
    project = tmp_path / "project"

    assert (
        main(
            [
                "init",
                str(project),
                "--target",
                "program",
                "--artifact",
                "build/grind.exe",
                "--oracle",
                "reference/grind.exe",
            ]
        )
        == 0
    )
    shutil.copyfile(GRIND_SAMPLE / "transform.cpp", project / "transform.cpp")
    shutil.copyfile(GRIND_SAMPLE / "prepare_reference.py", project / "prepare_reference.py")
    shutil.copyfile(
        GRIND_SAMPLE / "reprobit/discovery.json",
        project / "reprobit/discovery.json",
    )
    (project / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.20)\n"
        "project(reprobit_import_fixture CXX)\n"
        'set(CMAKE_CXX_FLAGS "")\n'
        'set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/Zi /O2 /Ob1")\n'
        'set(CMAKE_EXE_LINKER_FLAGS "")\n'
        'set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "")\n'
        'set(CMAKE_CXX_STANDARD_LIBRARIES "")\n'
        "add_executable(grind transform.cpp)\n"
        "target_include_directories(grind PRIVATE .)\n"
        "target_link_options(grind PRIVATE "
        "/nodefaultlib /entry:transform /subsystem:console)\n"
        "set_target_properties(grind PROPERTIES OUTPUT_NAME grind)\n",
        encoding="utf-8",
    )
    assert (
        main(
            [
                "setup",
                str(project),
                "--toolchain-root",
                str(toolchain),
                "--no-save",
                "--skip-probe",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "source",
                "lock",
                "--project",
                str(project),
                "--path",
                "reprobit.toml",
                "--path",
                "CMakeLists.txt",
                "--path",
                "transform.cpp",
            ]
        )
        == 0
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
    assert (project / "reference/grind.exe").is_file()
    assert (project / "reference/reference.obj").is_file()

    assert (
        main(
            [
                "import",
                "cmake",
                str(project),
                "--target",
                "program=grind",
                "--toolchain-root",
                str(toolchain),
            ]
        )
        == 0
    )

    bundle = load_project_tree(project)
    assert bundle.producer_graph is not None
    assert bundle.build_plan is not None
    assert len(bundle.build_plan.translation_units) == 1
    unit = bundle.build_plan.translation_units[0]
    assert unit.source == "transform.cpp"
    assert (project / "reprobit/interventions" / f"{unit.id}.json").is_file()
    assert (project / "reprobit/proofs" / f"{unit.id}.json").is_file()
    assert enumerate_project_grind_campaign(project).eligible_units == 1
    _seed_timestamp_normalization(project)

    assert (
        main(
            [
                "build",
                str(project),
                "--toolchain-root",
                str(toolchain),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "discover",
                "grind",
                str(project),
                "--project-wide",
                "--reference-object",
                f"{unit.id}=reference/reference.obj",
                "--accept-exact",
                "--toolchain-root",
                str(toolchain),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "verify",
                str(project),
                "--toolchain-root",
                str(toolchain),
            ]
        )
        == 0
    )
