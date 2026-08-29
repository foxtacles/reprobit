from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from io import StringIO
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

from reprobit.cache import IncrementalCache, cache_key
from reprobit.classic_project import ClassicProjectError
from reprobit.cli import (
    _human_intervention_detail,
    _legacy_oracle_targets,
    _positive_seconds,
    main,
)
from reprobit.cli_output import CLIOutput, human_command
from reprobit.cli_paths import CLIError
from reprobit.costs import calculate_cost
from reprobit.discovery_cli import (
    _discovery_wineserver_lifecycle,
    _resolve_paths,
    _run_discovery_wineserver_command,
)
from reprobit.incremental import IncrementalBuildSummary
from reprobit.migration import MigrationOutput
from reprobit.model import (
    Artifact,
    ArtifactKind,
    ArtifactOrigin,
    AuthenticityPolicy,
    ByteRange,
    Digest,
    ProvenanceKind,
    ProvenanceNode,
    Scope,
    Verdict,
)
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerGraphError,
    ProducerNode,
    ProducerRole,
)
from reprobit.progress import ProgressKind
from reprobit.project_loader import load_project, load_project_tree
from reprobit.report import (
    BuildExecutionSummary,
    ComponentIdentity,
    ExecutionFileReceipt,
    ExecutionStepReceipt,
    ProducerSummary,
    ProofReport,
    Report,
    RuntimeBindingPreimage,
    RuntimeProofBinding,
    TargetComparisonSummary,
)
from reprobit.report_io import write_report_json
from reprobit.schema import (
    AuthenticitySettings,
    BuildPlanDocument,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicTargetGate,
    ClassicTranslationUnitPlan,
    InterventionDocument,
    LegacyAllowlistEntry,
    LegacyOracleInstallIntervention,
    LinkOrderingIntervention,
    LockedTool,
    MsvcRelease,
    OracleDocument,
    OracleInstallRange,
    ProjectBundle,
    ProofDocument,
    StateCarrierIntervention,
    ToolchainLock,
    ToolchainProfileSource,
    source_manifest_digest,
)
from reprobit.source_lock import build_source_manifest
from reprobit.state import KeepWorkspace, RunArena
from reprobit.strict_json import canonical_json, strict_load
from reprobit.toolchains import MSVC_42, TOOLCHAIN_PROFILES, profile_source_pins_for_paths
from reprobit.transactions import CASTransaction, TransactionResult


def _initialize(root: Path) -> None:
    assert (
        main(
            [
                "init",
                str(root),
                "--project-id",
                "sample",
                "--artifact",
                "out/program.bin",
                "--oracle",
                "reference/program.bin",
            ]
        )
        == 0
    )


def test_cli_treats_a_closed_output_pipe_as_normal_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ClosedPipe(StringIO):
        def write(self, value: str) -> int:
            del value
            raise BrokenPipeError

    monkeypatch.setattr(sys, "stdout", ClosedPipe())

    assert main(["cmake-module"]) == 0


def _write_discovery_request(tmp_path: Path, *, source: str | None = None) -> Path:
    example = (
        Path(__file__).parents[1]
        / "examples"
        / "declaration-discovery"
        / "campaign.json"
    )
    document = strict_load(example)
    assert isinstance(document, dict)
    if source is not None:
        document["source"] = source
    request = tmp_path / "campaign.json"
    request.write_bytes(canonical_json(document))
    return request


def test_discover_rejects_report_aliasing_input_by_case(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _write_discovery_request(tmp_path, source="reference.json")

    assert (
        main(
            [
                "discover",
                "run",
                str(request),
                "--toolchain-root",
                str(tmp_path / "unused-toolchain"),
                "--report-json",
                "REFERENCE.JSON",
            ]
        )
        == 2
    )
    assert "report path overlaps a campaign input" in capsys.readouterr().err


def test_discover_rejects_input_paths_aliasing_by_case(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _write_discovery_request(tmp_path, source="REFERENCE.OBJ")

    assert (
        main(
            [
                "discover",
                "run",
                str(request),
                "--toolchain-root",
                str(tmp_path / "unused-toolchain"),
            ]
        )
        == 2
    )
    assert "inputs alias under case-insensitive path rules" in capsys.readouterr().err


def test_discover_keeps_report_outside_incremental_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _write_discovery_request(tmp_path)

    assert (
        main(
            [
                "discover",
                "run",
                str(request),
                "--toolchain-root",
                str(tmp_path / "unused-toolchain"),
                "--report-html",
                ".REPROBIT-DISCOVERY/runtime/session.html",
            ]
        )
        == 2
    )
    assert "report paths must not overlap discovery state" in capsys.readouterr().err


def test_discover_keeps_inputs_outside_incremental_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _write_discovery_request(tmp_path, source="STATE/source.cpp")

    assert (
        main(
            [
                "discover",
                "run",
                str(request),
                "--toolchain-root",
                str(tmp_path / "unused-toolchain"),
                "--state-directory",
                "state",
            ]
        )
        == 2
    )
    assert "state directory contains campaign input" in capsys.readouterr().err


def test_discover_report_outputs_default_and_derive_as_a_sibling(tmp_path: Path) -> None:
    request = _write_discovery_request(tmp_path)
    defaults = _resolve_paths(
        SimpleNamespace(
            request=str(request),
            report_json=None,
            report_html=None,
            state_directory=".state",
        )
    )
    from_json = _resolve_paths(
        SimpleNamespace(
            request=str(request),
            report_json="reports/review.json",
            report_html=None,
            state_directory=".state",
        )
    )
    from_html = _resolve_paths(
        SimpleNamespace(
            request=str(request),
            report_json=None,
            report_html="reports/findings.html",
            state_directory=".state",
        )
    )

    assert defaults.report_json == Path("campaign.report.json")
    assert defaults.report_html == Path("campaign.report.html")
    assert from_json.report_html == Path("reports/review.html")
    assert from_html.report_json == Path("reports/findings.json")


def test_discover_requires_paired_reports_to_be_siblings(tmp_path: Path) -> None:
    request = _write_discovery_request(tmp_path)

    with pytest.raises(CLIError, match="must be sibling files"):
        _resolve_paths(
            SimpleNamespace(
                request=str(request),
                report_json="json/review.json",
                report_html="html/review.html",
                state_directory=".state",
            )
        )


def test_discover_has_no_ambiguous_output_flag(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _write_discovery_request(tmp_path)

    with pytest.raises(SystemExit) as raised:
        main(
            [
                "discover",
                "run",
                str(request),
                "--toolchain-root",
                str(tmp_path / "unused-toolchain"),
                "--output",
                "review.json",
            ]
        )

    assert raised.value.code == 2
    assert "unrecognized arguments: --output" in capsys.readouterr().err


def test_discovery_wineserver_lifecycle_clears_and_reaps_each_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []

    def fake_control(**kwargs: object) -> None:
        calls.append((str(kwargs["phase"]), str(kwargs["argument"])))

    monkeypatch.setattr(
        "reprobit.discovery_cli._run_discovery_wineserver_command",
        fake_control,
    )
    arguments = {
        "executable": tmp_path / "wineserver",
        "runtime_root": tmp_path,
        "environment": {"WINEPREFIX": os.fspath(tmp_path / "prefix")},
        "timeout_seconds": 1.0,
    }

    for run in range(2):
        with _discovery_wineserver_lifecycle(**arguments):
            calls.append(("body", str(run)))

    assert calls == [
        ("preflight", "-k"),
        ("preflight", "-w"),
        ("body", "0"),
        ("cleanup", "-k"),
        ("cleanup", "-w"),
        ("preflight", "-k"),
        ("preflight", "-w"),
        ("body", "1"),
        ("cleanup", "-k"),
        ("cleanup", "-w"),
    ]


def test_discovery_wineserver_stop_accepts_an_already_stopped_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from reprobit.process import CommandFailed, ProcessResult

    def no_server(_supervisor: object, specification: object) -> None:
        result = ProcessResult(
            argv=(str(tmp_path / "wineserver"), "-k"),
            returncode=1,
            output=b"",
            attempts=1,
            duration_seconds=0.0,
        )
        raise CommandFailed(result, specification)

    monkeypatch.setattr("reprobit.process.ProcessSupervisor.run", no_server)

    _run_discovery_wineserver_command(
        executable=tmp_path / "wineserver",
        runtime_root=tmp_path,
        environment={"WINEPREFIX": os.fspath(tmp_path / "prefix")},
        timeout_seconds=1.0,
        argument="-k",
        phase="preflight",
    )


def test_discovery_wineserver_cleanup_preserves_primary_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = RuntimeError("campaign failed")

    def fake_control(**kwargs: object) -> None:
        if kwargs["phase"] == "cleanup" and kwargs["argument"] == "-k":
            raise CLIError("fake cleanup failure")

    monkeypatch.setattr(
        "reprobit.discovery_cli._run_discovery_wineserver_command",
        fake_control,
    )

    with (
        pytest.raises(RuntimeError, match="campaign failed") as caught,
        _discovery_wineserver_lifecycle(
            executable=tmp_path / "wineserver",
            runtime_root=tmp_path,
            environment={"WINEPREFIX": os.fspath(tmp_path / "prefix")},
            timeout_seconds=1.0,
        ),
    ):
        raise primary

    assert caught.value is primary
    assert any("Wine cleanup also failed" in note for note in caught.value.__notes__)


def test_discovery_wineserver_cleanup_failure_is_not_silent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_control(**kwargs: object) -> None:
        if kwargs["phase"] == "cleanup":
            raise CLIError(f"fake {kwargs['argument']} cleanup failure")

    monkeypatch.setattr(
        "reprobit.discovery_cli._run_discovery_wineserver_command",
        fake_control,
    )

    with (
        pytest.raises(CLIError, match="fake -k cleanup failure; fake -w cleanup failure"),
        _discovery_wineserver_lifecycle(
            executable=tmp_path / "wineserver",
            runtime_root=tmp_path,
            environment={"WINEPREFIX": os.fspath(tmp_path / "prefix")},
            timeout_seconds=1.0,
        ),
    ):
        pass


def test_source_lock_transactionally_replaces_the_explicit_read_set(tmp_path: Path) -> None:
    _initialize(tmp_path)
    (tmp_path / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.20)\n", encoding="utf-8"
    )
    assert (
        main(
            [
                "source",
                "lock",
                "--project",
                str(tmp_path),
                "--path",
                "reprobit.toml",
                "--path",
                "CMakeLists.txt",
            ]
        )
        == 0
    )
    document = strict_load(tmp_path / "reprobit/source-manifest.json")
    assert isinstance(document, dict)
    assert document["complete"] is True
    assert [item["path"] for item in document["entries"]] == [
        "CMakeLists.txt",
        "reprobit.toml",
    ]


def test_default_source_lock_omits_intentionally_deleted_tracked_file(
    tmp_path: Path,
) -> None:
    _initialize(tmp_path)
    removed = tmp_path / "obsolete.cpp"
    removed.write_bytes(b"int obsolete;\n")
    subprocess.run(("git", "init", "-q"), cwd=tmp_path, check=True)
    subprocess.run(("git", "add", "reprobit.toml", "obsolete.cpp"), cwd=tmp_path, check=True)
    removed.unlink()

    assert main(["source", "lock", "--project", str(tmp_path)]) == 0
    document = strict_load(tmp_path / "reprobit/source-manifest.json")
    assert isinstance(document, dict)
    assert [item["path"] for item in document["entries"]] == ["reprobit.toml"]


def test_source_preview_reports_stale_tu_and_lock_preserves_reviewed_authority(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    unit_id, _ = _complete_translation_unit_project(project)
    capsys.readouterr()
    manifest_path = project / "reprobit/source-manifest.json"
    plan_path = project / "reprobit/build-plan.json"
    unit_path = project / "reprobit/interventions/unit.json"
    proof_path = project / "reprobit/proofs/program.proof.json"
    before = {path: path.read_bytes() for path in (manifest_path, plan_path, unit_path, proof_path)}
    (project / "src/unit.cpp").write_bytes(b"int main() { return 1; }\n")
    paths = [
        "--path",
        "notes.txt",
        "--path",
        "reprobit.toml",
        "--path",
        "src/unit.cpp",
    ]

    assert (
        main(
            [
                "--format",
                "ndjson",
                "source",
                "preview",
                "--project",
                str(project),
                *paths,
            ]
        )
        == 0
    )
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert events[0]["event"] == "workflow_progress"
    event = events[-1]
    assert event["event"] == "source_preview"
    assert event["authority_regeneration_required"] is True
    assert event["changed"][0]["path"] == "src/unit.cpp"
    assert event["stale_translation_units"][0]["translation_unit_id"] == unit_id
    assert all(path.read_bytes() == data for path, data in before.items())

    assert main(["source", "lock", "--project", str(project), *paths]) == 2
    assert "regenerate" in capsys.readouterr().err
    assert all(path.read_bytes() == data for path, data in before.items())


def test_validate_rejects_current_manifest_with_stale_effective_tu_pin(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    _complete_translation_unit_project(project)
    capsys.readouterr()
    source = project / "src/unit.cpp"
    source.write_bytes(b"int main() { return 2; }\n")
    spec = load_project(project)
    manifest = build_source_manifest(
        project,
        ("notes.txt", "reprobit.toml", "src/unit.cpp"),
        spec=spec,
    )
    (project / spec.layout.source_manifest).write_bytes(canonical_json(manifest))
    plan_path = project / spec.layout.build_plan
    plan = BuildPlanDocument.model_validate_json(plan_path.read_bytes()).model_copy(
        update={"source_manifest_digest": source_manifest_digest(manifest)}
    )
    plan_path.write_bytes(canonical_json(plan))

    assert main(["validate", str(project)]) == 2
    message = capsys.readouterr().err
    assert "effective translation-unit source differs" in message
    assert "regenerate intervention and proof authority" in message


def test_source_lock_refreshes_unrelated_input_without_repinning_tu_or_proof(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    _, source_digest = _complete_translation_unit_project(project)
    capsys.readouterr()
    plan_path = project / "reprobit/build-plan.json"
    unit_path = project / "reprobit/interventions/unit.json"
    proof_path = project / "reprobit/proofs/program.proof.json"
    unit_before = unit_path.read_bytes()
    proof_before = proof_path.read_bytes()
    (project / "notes.txt").write_bytes(b"second note\n")
    paths = [
        "--path",
        "notes.txt",
        "--path",
        "reprobit.toml",
        "--path",
        "src/unit.cpp",
    ]

    assert main(["source", "lock", "--project", str(project), *paths]) == 0
    capsys.readouterr()
    plan = BuildPlanDocument.model_validate_json(plan_path.read_bytes())
    assert plan.translation_units[0].source_digest == source_digest
    assert unit_path.read_bytes() == unit_before
    assert proof_path.read_bytes() == proof_before
    assert load_project_tree(project).build_plan == plan


def test_source_lock_aborts_when_an_admitted_input_races_the_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    _complete_translation_unit_project(project)
    capsys.readouterr()
    manifest_path = project / "reprobit/source-manifest.json"
    plan_path = project / "reprobit/build-plan.json"
    manifest_before = manifest_path.read_bytes()
    plan_before = plan_path.read_bytes()
    notes = project / "notes.txt"
    notes.write_bytes(b"candidate note\n")
    original_commit = CASTransaction.commit

    def race_source(transaction: CASTransaction) -> TransactionResult:
        notes.write_bytes(b"raced note\n")
        return original_commit(transaction)

    monkeypatch.setattr(CASTransaction, "commit", race_source)
    assert (
        main(
            [
                "source",
                "lock",
                "--project",
                str(project),
                "--path",
                "notes.txt",
                "--path",
                "reprobit.toml",
                "--path",
                "src/unit.cpp",
            ]
        )
        == 2
    )
    assert "preimage conflict" in capsys.readouterr().err
    assert manifest_path.read_bytes() == manifest_before
    assert plan_path.read_bytes() == plan_before


def _complete_project(root: Path, *, command_build: bool = False) -> None:
    _initialize(root)
    if command_build:
        program = (
            "from pathlib import Path; Path('out').mkdir(exist_ok=True); "
            "Path('out/program.bin').write_bytes(b'expected')"
        )
        (root / "reprobit.toml").write_text(
            "\n".join(
                (
                    "schema_version = 3",
                    'project_id = "sample"',
                    'state_dir = ".reprobit-state"',
                    "",
                    "[build]",
                    'kind = "command"',
                    "",
                    "[[build.build]]",
                    f"argv = {json.dumps([sys.executable, '-c', program])}",
                    'cwd = "."',
                    "timeout_seconds = 30",
                    "",
                    "[toolchain]",
                    'adapter = "classic-msvc"',
                    'profile = "msvc_4_2"',
                    'lock_file = "reprobit/toolchain.lock.json"',
                    "",
                    "[paths]",
                    'id = "dos-stable-v1"',
                    "source = 'R:\\source'",
                    "build = 'R:\\build'",
                    "toolchain = 'R:\\toolchain'",
                    "",
                    "[verifier]",
                    'kind = "literal"',
                    "",
                    "[authenticity]",
                    'policy = "clean"',
                    "",
                    "[[targets]]",
                    'id = "program"',
                    'artifact = "out/program.bin"',
                    'oracle = "reference/program.bin"',
                    "",
                )
            ),
            encoding="utf-8",
        )
        assert (
            main(
                [
                    "source",
                    "lock",
                    "--project",
                    str(root),
                    "--path",
                    "reprobit.toml",
                ]
            )
            == 0
        )
    reference = root / "reference" / "program.bin"
    reference.parent.mkdir()
    reference.write_bytes(b"expected")
    toolchain_profile = TOOLCHAIN_PROFILES[MSVC_42]
    locked_paths = (
        *toolchain_profile.required_producers,
        *toolchain_profile.required_runtime_files,
    )
    source_pins = profile_source_pins_for_paths(toolchain_profile, locked_paths)
    producer_roles = {
        toolchain_profile.compiler.casefold(): ("compiler",),
        toolchain_profile.linker.casefold(): ("linker",),
        toolchain_profile.librarian.casefold(): ("librarian",),
        toolchain_profile.resource_compiler.casefold(): ("resource-compiler",),
    }
    lock = ToolchainLock(
        schema_version=3,
        profile=MSVC_42,
        release=MsvcRelease.V4_2,
        profile_sources=tuple(
            ToolchainProfileSource(
                repository=source.repository,
                revision=source.revision,
                paths=source.paths,
            )
            for source in source_pins
        ),
        tools=tuple(
            LockedTool(
                id=f"producer.{index}",
                path=path,
                digest=Digest.from_bytes(path.encode()),
                size=len(path.encode()),
                roles=producer_roles.get(path.casefold(), ("runtime",)),
            )
            for index, path in enumerate(toolchain_profile.required_producers)
        ),
        runtime_files=tuple(
            LockedTool(
                id=f"runtime.{index}",
                path=path,
                digest=Digest.from_bytes(path.encode()),
                size=len(path.encode()),
                roles=("runtime",),
            )
            for index, path in enumerate(toolchain_profile.required_runtime_files)
        ),
    )
    intervention = StateCarrierIntervention(
        id="state.one",
        scope=Scope(target="program"),
        rationale="stabilize one compiler state carrier",
        carrier="state.carrier",
    )
    documents = {
        root / "reprobit" / "toolchain.lock.json": canonical_json(lock),
        root / "reprobit" / "interventions" / "program.json": canonical_json(
            InterventionDocument(
                schema_version=3,
                target_id="program",
                interventions=(intervention,),
            )
        ),
        root / "reprobit" / "proofs" / "program.proof.json": canonical_json(
            ProofDocument(schema_version=3, target_id="program")
        ),
        root / "reprobit" / "oracles" / "program.json": canonical_json(
            OracleDocument(
                schema_version=3,
                target_id="program",
                image_size=len(b"expected"),
                image_digest=Digest.from_bytes(b"expected"),
            )
        ),
    }
    for path, data in documents.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def _complete_translation_unit_project(root: Path) -> tuple[str, Digest]:
    _complete_project(root)
    source = root / "src/unit.cpp"
    source.parent.mkdir()
    source.write_bytes(b"int main() { return 0; }\n")
    (root / "notes.txt").write_bytes(b"first note\n")
    spec = load_project(root)
    manifest = build_source_manifest(
        root,
        ("notes.txt", "reprobit.toml", "src/unit.cpp"),
        spec=spec,
    )
    (root / spec.layout.source_manifest).write_bytes(canonical_json(manifest))
    source_digest = Digest.from_bytes(source.read_bytes())
    unit_id = "tu.program.unit"
    plan = BuildPlanDocument(
        schema_version=3,
        source_manifest_digest=source_manifest_digest(manifest),
        translation_units=(
            ClassicTranslationUnitPlan(
                id=unit_id,
                target_id="program",
                build_target="program",
                source="src/unit.cpp",
                source_digest=source_digest,
            ),
        ),
        source_overlay_digest=Digest.from_bytes(b"no source overlays"),
        source_overlay_interventions=(),
        archives=(),
        target_gates=(
            ClassicTargetGate(
                target_id="program",
                build_target="program",
            ),
        ),
    )
    (root / spec.layout.build_plan).write_bytes(canonical_json(plan))
    unit_document = InterventionDocument(
        schema_version=3,
        target_id="program",
        translation_unit_id=unit_id,
        source="src/unit.cpp",
        source_digest=source_digest,
        build_target="program",
    )
    unit_path = root / spec.layout.interventions / "unit.json"
    unit_path.parent.mkdir(parents=True, exist_ok=True)
    unit_path.write_bytes(canonical_json(unit_document))
    load_project_tree(root)
    return unit_id, source_digest


def test_validate_rejects_missing_known_profile_source_mapping(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = tmp_path / "project"
    _complete_project(project)
    capsys.readouterr()
    lock_path = project / "reprobit/toolchain.lock.json"
    document = strict_load(lock_path)
    assert isinstance(document, dict)
    document["profile_sources"] = []
    lock_path.write_bytes(canonical_json(document))

    assert main(["validate", str(project)]) == 2
    assert "profile-source assignment set differs" in capsys.readouterr().err


def test_cli_legacy_oracle_targets_rejects_validated_project_scoped_orphan(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _complete_translation_unit_project(project)
    bundle = load_project_tree(project)
    receipt = ClassicProofReceipt(
        id="proof.legacy.orphan",
        intervention_id="legacy.orphan",
        family=ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION,
    )
    action = LegacyOracleInstallIntervention.freeze(
        id="legacy.orphan",
        scope=Scope(target="program"),
        rationale="validated project-scoped temporary classic orphan",
        dependencies=("state.one",),
        proof_receipt_digest=Digest.from_bytes(canonical_json(receipt)),
        preimage_digest=Digest.from_bytes(b"preimage"),
        oracle_body_digest=Digest.from_bytes(b"oracle"),
        oracle_target="program",
        oracle_address=0,
        ranges=(
            OracleInstallRange(
                preimage_range=ByteRange(offset=0, length=1),
                output_range=ByteRange(offset=0, length=1),
                oracle_range=ByteRange(offset=0, length=1),
            ),
        ),
        byte_count=1,
        maximum_oracle_payload_bytes=1,
    )
    allowlist = LegacyAllowlistEntry(
        intervention_id=action.id,
        allowlist_digest=action.allowlist_digest,
        proof_receipt_digest=action.proof_receipt_digest,
        range_count=len(action.ranges),
        byte_count=action.byte_count,
        maximum_oracle_payload_bytes=action.maximum_oracle_payload_bytes,
    )
    spec = bundle.spec.model_copy(
        update={
            "authenticity": AuthenticitySettings(
                policy=AuthenticityPolicy.ALLOW_QUARANTINE,
                legacy_allowlist=(allowlist,),
            )
        }
    )
    validated = ProjectBundle(
        root=bundle.root,
        spec=spec,
        toolchain_lock=bundle.toolchain_lock,
        source_manifest=bundle.source_manifest,
        build_plan=bundle.build_plan,
        producer_graph=bundle.producer_graph,
        intervention_documents=(
            *bundle.intervention_documents,
            InterventionDocument(
                schema_version=3,
                target_id="program",
                interventions=(action,),
            ),
        ),
        proof_documents=(
            *bundle.proof_documents,
            ProofDocument(
                schema_version=3,
                target_id="program",
                expected_observations=(receipt,),
            ),
        ),
        oracle_documents=bundle.oracle_documents,
    )
    assert validated.interventions[-1] == action

    with pytest.raises(
        ClassicProjectError,
        match="is outside a planned translation-unit shard",
    ):
        _legacy_oracle_targets(validated)


def _migration_files(source: Path) -> dict[PurePosixPath, bytes]:
    return {
        PurePosixPath(path.relative_to(source).as_posix()): path.read_bytes()
        for path in source.rglob("*")
        if path.is_file() and ".reprobit-transactions" not in path.parts
    }


def test_graph_configure_exposes_closed_migration_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    _complete_project(project)
    # This command prepares metadata for a replacement graph.  The graph being
    # replaced must not prevent configuration after another authority (most
    # commonly the toolchain lock) was deliberately refreshed.
    (project / "reprobit/producer-graph.json").write_bytes(b"stale graph")
    with pytest.raises(ProducerGraphError):
        load_project_tree(project)
    capsys.readouterr()
    toolchain = tmp_path / "toolchain"
    toolchain.mkdir()
    workspace = tmp_path / "migration"
    captured: dict[str, object] = {}

    def configure(bundle: ProjectBundle, **options: object) -> SimpleNamespace:
        captured.update(options)
        assert bundle.spec.project_id == "sample"
        return SimpleNamespace(
            configured_build_root=workspace / "build",
            effective_source_root=workspace / "source",
            toolchain_root=toolchain,
            target_plan=workspace / "build/reprobit-target-plan.json",
            compile_database=workspace / "build/compile_commands.json",
            project_plan=workspace / "reprobit-project-plan.cmake",
            configure_log=workspace / "build/configure.log",
            command_digest=Digest.from_bytes(b"configure"),
            duration_seconds=1.25,
        )

    monkeypatch.setattr("reprobit.classic_migration.configure_classic_producer_graph", configure)
    assert (
        main(
            [
                "--format",
                "ndjson",
                "graph",
                "configure",
                "--project",
                str(project),
                "--workspace-root",
                str(workspace),
                "--toolchain-root",
                str(toolchain),
                "--cmake",
                sys.executable,
                "--compiler-transport",
                sys.executable,
                "--resource-transport",
                sys.executable,
                "--timeout",
                "30",
            ]
        )
        == 0
    )
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert events[0]["event"] == "workflow_progress"
    event = events[-1]
    assert event["event"] == "producer_graph_configured"
    assert event["certification_runtime"] is False
    assert event["configured_build_root"] == str(workspace / "build")
    assert captured["timeout_seconds"] == 30.0
    assert captured["workspace_root"] == workspace


def test_init_is_transactional_and_emits_stable_ndjson(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "project"
    assert (
        main(
            [
                "--format",
                "ndjson",
                "init",
                str(root),
                "--project-id",
                "sample",
            ]
        )
        == 0
    )
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(events) == 1
    event = events[-1]
    assert event["event"] == "initialized"
    initialized = load_project(root)
    assert initialized.project_id == "sample"
    assert initialized.build.kind == "producer-graph"

    assert main(["init", str(root), "--project-id", "sample"]) == 2
    assert "preimage conflict" in capsys.readouterr().err


@pytest.mark.skipif(os.name != "posix", reason="Wine backend is supported only on POSIX")
def test_doctor_never_executes_wine_without_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "reprobit.backends.subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("probe executed")),
    )
    assert (
        main(
            [
                "doctor",
                str(tmp_path),
                "--backend",
                "posix_wine_v1",
                "--wine",
                sys.executable,
                "--wineserver",
                sys.executable,
            ]
        )
        == 0
    )


def test_toolchain_lock_commits_only_schema_v3(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _initialize(project)
    lock_path = project / "reprobit" / "toolchain.lock.json"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_bytes(
        canonical_json(
            {
                "schema_version": 3,
                "profile": MSVC_42,
                "release": "4.2",
                "source_revision": "0" * 40,
                "tools": [],
            }
        )
    )
    installation = tmp_path / "toolchain"
    profile = TOOLCHAIN_PROFILES[MSVC_42]
    for relative in (*profile.required_producers, *profile.required_runtime_files):
        path = installation.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(relative.encode())
    for relative in (*profile.include_roots, *profile.library_roots):
        path = installation.joinpath(*relative.split("/"))
        path.mkdir(parents=True, exist_ok=True)
        (path / "input.h").write_text(relative)
    wrapper = installation / "wine" / "x86" / "cl"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_bytes(b"explicit wrapper")

    assert (
        main(
            [
                "toolchain",
                "lock",
                "--project",
                str(project),
                "--root",
                str(installation),
                "--runtime-file",
                "wine/x86/cl",
            ]
        )
        == 0
    )

    document = strict_load(lock_path)
    assert isinstance(document, dict)
    assert document["schema_version"] == 3
    assert document["profile"] == MSVC_42
    assert "schema" not in document
    assert "source_revision" not in document
    assert "sources" not in document
    assert len(document["profile_sources"]) == 2
    assert len(document["runtime_files"]) == len(profile.required_runtime_files) + 1
    assert {item["path"] for item in document["runtime_files"]} >= {"wine/x86/cl"}
    assigned_paths = {
        path.casefold() for source in document["profile_sources"] for path in source["paths"]
    }
    assert "wine/x86/cl" not in assigned_paths
    assert len(document["input_trees"]) == len(profile.include_roots + profile.library_roots)


def test_graph_extract_commits_closed_direct_producer_authority(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = tmp_path / "project"
    _complete_project(project)
    project_file = project / "reprobit.toml"
    project_file.write_text(
        project_file.read_text(encoding="utf-8").replace(
            'artifact = "out/program.bin"', 'artifact = "build/APP.EXE"'
        ),
        encoding="utf-8",
    )
    source = project / "src/unit.cpp"
    source.parent.mkdir()
    source.write_text("int main() { return 0; }\n", encoding="utf-8")
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
                "src/unit.cpp",
            ]
        )
        == 0
    )
    capsys.readouterr()

    configured = tmp_path / "configured"
    toolchain = tmp_path / "toolchain"
    compiler = toolchain / "wine/x86/cl"
    linker = toolchain / "wine/x86/link"
    for producer in (compiler, linker):
        producer.parent.mkdir(parents=True, exist_ok=True)
        producer.write_text("fixture\n", encoding="utf-8")
    configured.mkdir()
    object_path = "CMakeFiles/program.dir/src/unit.cpp.obj"
    pdb_path = object_path + ".pdb"
    (configured / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": str(configured),
                    "file": str(source),
                    "command": " ".join(
                        (
                            str(compiler),
                            "/nologo",
                            f"/Fo{object_path}",
                            f"/Fd{pdb_path}",
                            "/c",
                            str(source),
                        )
                    ),
                }
            ]
        ),
        encoding="utf-8",
    )
    link_directory = configured / "CMakeFiles/program.dir"
    link_directory.mkdir(parents=True)
    link_file = link_directory / "link.txt"
    link_file.write_text(f"{linker} {object_path} /out:APP.EXE\n", encoding="utf-8")
    (configured / "reprobit-target-plan.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "targets": [
                    {
                        "name": "program",
                        "artifact_id": "program",
                        "output": str(configured / "APP.EXE"),
                        "pdb": None,
                    }
                ],
                "link_admissions": [],
            }
        ),
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--format",
                "ndjson",
                "graph",
                "extract",
                "--project",
                str(project),
                "--configured-build-root",
                str(configured),
                "--effective-source-root",
                str(project),
                "--toolchain-root",
                str(toolchain),
                "--directive-input",
                "program=MFCS42",
            ]
        )
        == 0
    )
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert events[0]["event"] == "workflow_progress"
    event = events[-1]
    assert event["event"] == "producer_graph_extracted"
    assert event["roles"] == {
        "compiler": 1,
        "librarian": 0,
        "linker": 1,
        "resource-compiler": 0,
    }
    bundle = load_project_tree(project)
    assert bundle.producer_graph is not None
    terminal = next(node for node in bundle.producer_graph.nodes if node.target_id == "program")
    assert terminal.outputs == ("build/APP.EXE",)
    assert terminal.directive_inputs == ("system-library/mfcs42.lib",)

    graph_path = project / "reprobit/producer-graph.json"
    committed_graph = graph_path.read_bytes()
    target_plan_path = configured / "reprobit-target-plan.json"
    target_plan_value = json.loads(target_plan_path.read_bytes())
    target_plan_value["link_admissions"] = [
        {
            "id": "unsupported",
            "target": "program",
            "artifact_id": "generated.object",
            "object_path": "R:/build/generated.obj",
            "insertion_index": None,
            "before": "runtime.lib",
            "after": None,
            "expected_symbol": "_entry",
        }
    ]
    target_plan_path.write_text(json.dumps(target_plan_value), encoding="utf-8")
    assert (
        main(
            [
                "graph",
                "extract",
                "--project",
                str(project),
                "--configured-build-root",
                str(configured),
                "--effective-source-root",
                str(project),
                "--toolchain-root",
                str(toolchain),
            ]
        )
        == 2
    )
    admission_error = capsys.readouterr()
    assert "link admissions" in admission_error.err
    assert graph_path.read_bytes() == committed_graph
    target_plan_value["link_admissions"] = []
    target_plan_path.write_text(json.dumps(target_plan_value), encoding="utf-8")

    for invalid_arguments in (
        ("--directive-input", "missing=mfcs42"),
        ("--directive-input", "program=vendor/mfcs42.lib"),
        (
            "--directive-input",
            "program=MFCS42",
            "--directive-input",
            "program=mfcs42.lib",
        ),
    ):
        assert (
            main(
                [
                    "graph",
                    "extract",
                    "--project",
                    str(project),
                    "--configured-build-root",
                    str(configured),
                    "--effective-source-root",
                    str(project),
                    "--toolchain-root",
                    str(toolchain),
                    *invalid_arguments,
                ]
            )
            == 2
        )
        assert (project / "reprobit/producer-graph.json").read_bytes() == committed_graph
        capsys.readouterr()

    link_file.write_text(f"{linker} {object_path} /out:UNDECLARED.EXE\n", encoding="utf-8")
    assert (
        main(
            [
                "graph",
                "extract",
                "--project",
                str(project),
                "--configured-build-root",
                str(configured),
                "--effective-source-root",
                str(project),
                "--toolchain-root",
                str(toolchain),
            ]
        )
        == 2
    )
    assert (project / "reprobit/producer-graph.json").read_bytes() == committed_graph
    capsys.readouterr()
    link_file.write_text(f"{linker} {object_path} /out:APP.EXE\n", encoding="utf-8")

    source.write_text("int main() { return 1; }\n", encoding="utf-8")
    lock_argv = [
        "source",
        "lock",
        "--project",
        str(project),
        "--path",
        "reprobit.toml",
        "--path",
        "src/unit.cpp",
    ]
    assert main(lock_argv) == 0
    assert (project / "reprobit/producer-graph.json").read_bytes() == committed_graph
    capsys.readouterr()

    added = project / "src/added.h"
    added.write_text("#pragma once\n", encoding="utf-8")
    topology_change = [*lock_argv, "--path", "src/added.h"]
    assert main(topology_change) == 2
    assert "--invalidate-producer-graph" in capsys.readouterr().err
    assert (project / "reprobit/producer-graph.json").is_file()
    assert main([*topology_change, "--invalidate-producer-graph"]) == 0
    assert not (project / "reprobit/producer-graph.json").exists()


def test_graph_upgrade_command_is_not_exposed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["graph", "upgrade"])

    assert stopped.value.code == 2
    message = capsys.readouterr().err
    assert "invalid choice: 'upgrade'" in message
    assert "configure" in message and "extract" in message


def test_version_is_available_for_packaging_smoke(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["--version"])

    assert stopped.value.code == 0
    assert capsys.readouterr().out.startswith("rbit ")


class _CapturedTTY(StringIO):
    def isatty(self) -> bool:
        return True


def test_producer_progress_is_structured_for_ndjson_and_restrained_for_text() -> None:
    machine = StringIO()
    with CLIOutput("ndjson", machine, StringIO()).producer_activity("build") as progress:
        progress(
            1,
            100,
            "compile",
            "unit.one",
            ProgressKind.CACHE_MISS,
            "recursive header changed",
        )
        progress(
            1,
            100,
            "analyze",
            "analyzing compiler products",
            ProgressKind.PHASE_STARTED,
        )
        progress(
            100,
            100,
            "terminal",
            "publish.program",
            ProgressKind.CACHE_HIT,
        )
    events = [json.loads(line) for line in machine.getvalue().splitlines()]
    assert [event["event"] for event in events] == [
        "workflow_progress",
        "producer_progress",
        "workflow_progress",
        "producer_progress",
        "workflow_progress",
    ]
    assert events[0]["kind"] == "phase_started"
    assert events[1]["kind"] == "cache_miss"
    assert events[1]["reason"] == "recursive header changed"
    assert events[2]["kind"] == "phase_started"
    assert events[2]["phase"] == "analyze"
    assert events[3]["kind"] == "cache_hit"
    assert events[-1]["kind"] == "phase_finished"
    assert events[-2]["completed"] == events[-2]["total"] == 100
    assert [event["sequence"] for event in events] == [1, 2, 3, 4, 5]

    human = StringIO()
    with CLIOutput("text", StringIO(), human).producer_activity("build") as progress:
        progress(1, 100, "compile", "unit.one", ProgressKind.CACHE_MISS)
        progress(2, 100, "compile", "unit.two", ProgressKind.CACHE_HIT)
        progress(9, 100, "compile", "unit.nine", ProgressKind.CACHE_HIT)
        progress(10, 100, "compile", "unit.ten", ProgressKind.CACHE_HIT)
        progress(100, 100, "terminal", "publish.program", ProgressKind.CACHE_HIT)
    lines = human.getvalue().splitlines()
    assert len(lines) == 5
    assert lines[0] == "build..."
    assert "1/100" in lines[1]
    assert "cache 0 hit/1 miss" in lines[1]
    assert "10/100" in lines[2]
    assert "100/100" in lines[3]
    assert lines[4].startswith("build: complete")


def test_interactive_producer_progress_is_transient_on_success() -> None:
    human = _CapturedTTY()
    with CLIOutput("text", StringIO(), human).producer_activity("build") as progress:
        progress(1, 2, "compile", "unit.one", ProgressKind.CACHE_MISS)
        progress(2, 2, "compile", "unit.two", ProgressKind.CACHE_HIT)

    assert "build: complete" not in human.getvalue()


def test_interactive_producer_progress_leaves_durable_failure_context() -> None:
    human = _CapturedTTY()
    with (
        pytest.raises(RuntimeError, match="producer failed"),
        CLIOutput("text", StringIO(), human).producer_activity("build") as progress,
    ):
        progress(1, 10, "compile", "unit.one", ProgressKind.CACHE_MISS)
        progress(
            1,
            10,
            "audit",
            "projection.unit.one",
            ProgressKind.PHASE_FAILED,
            "projection mismatch",
        )
        raise RuntimeError("producer failed")

    summary = human.getvalue().splitlines()[-1]
    # Rich may prefix the durable line with terminal cursor-clear controls.
    assert "build: failed after 1/10" in summary
    assert "s elapsed" in summary
    assert "last failure: audit: projection.unit.one: projection mismatch" in summary
    assert "error: producer failed" in summary
    assert "cache 0 hit/1 miss" in summary


def test_interactive_activity_is_transient_on_success_and_durable_on_failure() -> None:
    success = _CapturedTTY()
    with CLIOutput("text", StringIO(), success).activity("loading project"):
        pass
    assert "loading project: complete" not in success.getvalue()

    failure = _CapturedTTY()
    with (
        pytest.raises(RuntimeError, match="invalid project"),
        CLIOutput("text", StringIO(), failure).activity("loading project"),
    ):
        raise RuntimeError("invalid project")
    failed_summary = failure.getvalue().splitlines()[-1]
    # Rich may prefix the durable line with terminal cursor-clear controls.
    assert "loading project: failed (" in failed_summary
    assert "s elapsed; error: invalid project" in failed_summary


def test_redirected_progress_reports_latest_count_when_execution_fails() -> None:
    human = StringIO()
    with (
        pytest.raises(RuntimeError, match="producer failed"),
        CLIOutput("text", StringIO(), human).producer_activity("build") as progress,
    ):
        progress(1, 100, "compile", "unit.one")
        progress(9, 100, "compile", "unit.nine")
        raise RuntimeError("producer failed")

    lines = human.getvalue().splitlines()
    assert lines[0] == "build..."
    assert "1/100" in lines[1]
    assert lines[2] == (
        "build: failed (9/100; compile: unit.nine; error: producer failed)"
    )


def test_incremental_summary_is_complete_in_text_and_ndjson() -> None:
    summary = IncrementalBuildSummary(
        producer_hits=97,
        producer_misses=1,
        transform_hits=2,
        transform_misses=0,
        elapsed_seconds=1.25,
        runtime_init_count=1,
        invalidations=(("compile.unit", "recursive header changed"),),
        unchanged_targets=1,
    )
    human = StringIO()
    CLIOutput("text", human, StringIO()).incremental_summary(summary)
    rendered = human.getvalue()
    assert "99 reused, 1 rebuilt (99.0% reused)" in rendered
    assert "compiler environment started 1 time" in rendered
    assert "1.25s" in rendered
    assert "targets: 1 unchanged, 0 updated" in rendered
    assert "Why steps were rebuilt:" in rendered
    assert "compile.unit: recursive header changed" in rendered

    machine = StringIO()
    CLIOutput("ndjson", machine, StringIO()).incremental_summary(summary)
    event = json.loads(machine.getvalue())
    assert event["event"] == "incremental_build_summary"
    assert event["producer_hits"] == 97
    assert event["transform_hits"] == 2
    assert event["misses"] == 1
    assert event["hit_rate"] == 0.99
    assert event["runtime_init_count"] == 1
    assert event["published_targets"] == 0
    assert event["unchanged_targets"] == 1
    assert event["invalidations"] == [
        {"node_id": "compile.unit", "reason": "recursive header changed"}
    ]


def test_incremental_text_summary_bounds_invalidation_details() -> None:
    summary = IncrementalBuildSummary(
        producer_hits=0,
        producer_misses=10,
        transform_hits=0,
        transform_misses=0,
        elapsed_seconds=1.0,
        runtime_init_count=1,
        invalidations=tuple((f"compile.{index:02d}", f"reason {index}") for index in range(10)),
    )
    human = StringIO()

    CLIOutput("text", human, StringIO()).incremental_summary(summary)

    rendered = human.getvalue()
    assert "compile.07: reason 7" in rendered
    assert "compile.08: reason 8" not in rendered
    assert "... and 2 more" in rendered


def test_state_status_and_clean_expose_retained_workspace_lifecycle(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project with spaces"
    _complete_project(project)
    capsys.readouterr()
    state = project / ".reprobit-state"
    state.mkdir()
    with RunArena(
        state,
        kind="build",
        run_id="retained",
        keep=KeepWorkspace.ALWAYS,
    ) as arena:
        retained = arena.path
        (arena.path / "payload.bin").write_bytes(b"x" * 2048)

    cached_output = tmp_path / "cached-output.obj"
    cached_output.write_bytes(b"cached output")
    cache = IncrementalCache(state, implementation="cli-clean-test-v1")
    key = cache_key(
        "producer",
        {"node": "compile"},
        implementation="cli-clean-test-v1",
    )
    with cache.lease() as lease:
        lease.store("producer", key, {"build/output.obj": cached_output})

        assert main(["--format", "ndjson", "state", "status", str(project)]) == 0
        events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        status = events[-1]
        assert status["event"] == "state_status"
        assert status["run_bytes"] >= 2048
        assert status["runs"][0]["outcome"] == "succeeded"

        assert main(["clean", str(project), "--preview"]) == 0
        assert retained.is_dir()
        preview = capsys.readouterr().out
        assert "Clean preview:" in preview
        assert "1 inactive workspace" in preview
        assert "reusable incremental cache will be kept" in preview

        assert main(["clean", str(project)]) == 0
        assert not retained.exists()
        assert cache.status().records == 1
        cleaned = capsys.readouterr().out
        assert "Freed " in cleaned
        assert "1 inactive workspace" in cleaned
        assert "reusable incremental cache was kept" in cleaned

        assert main(["clean", str(project), "--cache"]) == 0
        skipped = capsys.readouterr().out
        assert "Cache cleanup was skipped because 1 active build" in skipped
        assert cache.status().records == 1

    assert (
        main(
            [
                "clean",
                str(project),
                "--older-than-hours",
                "24",
                "--cache",
                "--preview",
            ]
        )
        == 0
    )
    preview = capsys.readouterr().out
    expected = human_command(("rbit", "clean", project, "--older-than-hours", "24", "--cache"))
    assert f"Run {expected} to perform this cleanup." in preview
    assert "1 recent cache record" in preview
    assert cache.status().records == 1

    assert main(["clean", str(project), "--cache"]) == 0
    cleaned = capsys.readouterr().out
    assert "Removed 1 cache record" in cleaned
    assert cache.status().records == 0


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "not-a-number"])
def test_execution_timeouts_must_be_positive_and_finite(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError, match=r"number|greater than zero"):
        _positive_seconds(value)


def test_validate_explain_cost_build_and_cold_verify_refusal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = tmp_path / "project"
    _complete_project(project, command_build=True)
    capsys.readouterr()

    assert main(["validate", str(project)]) == 0
    assert "validated sample" in capsys.readouterr().out
    assert main(["cost", str(project)]) == 0
    assert "project intervention cost: 1 relative points" in capsys.readouterr().out
    assert main(["explain", str(project), "--intervention", "state.one"]) == 0
    assert "cost=1" in capsys.readouterr().out
    assert main(["build", str(project), "--cold"]) == 0
    assert (project / "out" / "program.bin").read_bytes() == b"expected"
    assert not any((project / ".reprobit-state" / "runs").iterdir())

    assert main(["verify", str(project)]) == 2
    assert "refuses command adapters" in capsys.readouterr().err


def test_cost_and_selected_explain_are_compact_in_text_and_complete_in_ndjson(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    _complete_project(project, command_build=True)
    capsys.readouterr()

    assert main(["cost", str(project)]) == 0
    cost_text = capsys.readouterr().out
    assert "project intervention cost: 1 relative points (model v2)" in cost_text
    assert "function attribution: 0 attributed, 1 unallocated project/TU shared" in cost_text
    assert "targets:\n  program: 1 (interventions=1, units=1)" in cost_text
    assert "classes:\n  state_carrier: 1 (interventions=1, units=1)" in cost_text

    assert main(["explain", str(project)]) == 0
    bulk_text = capsys.readouterr().out
    assert bulk_text.count("\n") == 1
    assert "rationale:" not in bulk_text

    assert main(["explain", str(project), "--intervention", "state.one"]) == 0
    selected_text = capsys.readouterr().out
    assert "cost class: state_carrier" in selected_text
    assert "typed units: intervention: 1 x 1 = 1" in selected_text
    assert "dependencies: none" in selected_text
    assert "shared beneficiaries: none" in selected_text
    assert "rationale: stabilize one compiler state carrier" in selected_text

    assert main(["--format", "ndjson", "cost", str(project)]) == 0
    cost_event = json.loads(capsys.readouterr().out)
    assert cost_event["breakdown"]["by_target"] == [
        {"cost": 1, "interventions": 1, "target": "program", "units": 1}
    ]
    assert cost_event["breakdown"]["by_class"] == [
        {"cost": 1, "cost_class": "state_carrier", "interventions": 1, "units": 1}
    ]

    assert (
        main(
            [
                "--format",
                "ndjson",
                "explain",
                str(project),
                "--intervention",
                "state.one",
            ]
        )
        == 0
    )
    explain_event = json.loads(capsys.readouterr().out)
    assert explain_event["cost_class"] == "state_carrier"
    assert explain_event["rationale"] == "stabilize one compiler state carrier"
    assert explain_event["dependencies"] == []
    assert explain_event["beneficiaries"] == []
    assert explain_event["units"] == [
        {"cost": 1, "count": 1, "kind": "intervention", "unit_cost": 1}
    ]


def test_selected_explain_names_shared_cost_beneficiaries() -> None:
    beneficiary = Scope(
        target="program",
        translation_unit="main",
        function="work()",
    )
    intervention = LinkOrderingIntervention(
        id="shared-order",
        scope=Scope(target="program"),
        rationale="attribute one shared ordering intervention",
        beneficiaries=(beneficiary,),
        item_ids=("first", "second"),
    )
    cost = calculate_cost((intervention,)).interventions[0]

    rendered = _human_intervention_detail(intervention, cost)

    assert "shared beneficiaries: program/main/work()" in rendered


def test_cost_and_explain_read_committed_metadata_without_hashing_dirty_sources(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    _complete_translation_unit_project(project)
    capsys.readouterr()
    (project / "src/unit.cpp").write_bytes(b"int main() { return 7; }\n")

    assert main(["cost", str(project)]) == 0
    assert "project intervention cost: 1 relative points" in capsys.readouterr().out
    assert main(["explain", str(project), "--intervention", "state.one"]) == 0
    assert "cost=1" in capsys.readouterr().out

    assert main(["validate", str(project)]) == 2
    assert "portable manifest" in capsys.readouterr().err


def test_cold_producer_build_and_verify_never_construct_incremental_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Cold developer and certifying paths stay outside cache initialization."""

    from reprobit.build import BuildPlan
    from reprobit.execution import BuildExecutionReceipt, FileReceipt

    project = tmp_path / "project"
    _complete_project(project)
    capsys.readouterr()
    prepared_calls: list[str] = []
    cold_requests: list[bool] = []
    bound_legacy_targets: list[frozenset[str]] = []

    class CacheBomb:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError("cold execution constructed the incremental cache")

    class FakeExecutor:
        def bind_legacy_oracles(self, oracles: object) -> None:
            assert isinstance(oracles, dict)
            bound_legacy_targets.append(frozenset(oracles))

        def execute(
            self,
            _plan: BuildPlan,
            *,
            cold: bool,
            required_outputs: tuple[Path, ...],
        ) -> BuildExecutionReceipt:
            assert cold is True
            cold_requests.append(cold)
            receipts: list[FileReceipt] = []
            for path in required_outputs:
                path.parent.mkdir(parents=True, exist_ok=True)
                payload = b"expected"
                path.write_bytes(payload)
                receipts.append(
                    FileReceipt(
                        path,
                        Digest.from_bytes(payload),
                        len(payload),
                        True,
                    )
                )
            return BuildExecutionReceipt(True, (), tuple(receipts), ())

    def prepare(*_args: object, **_kwargs: object) -> SimpleNamespace:
        prepared_calls.append("prepared")
        executor = FakeExecutor()
        return SimpleNamespace(
            executor=executor,
            donors=executor,
            evidence_provider=SimpleNamespace(name="cold-test-provider"),
            plan=BuildPlan(()),
            close=lambda: None,
        )

    class FakeVerificationResult:
        verdict = SimpleNamespace(clean=True, quarantined=False, quarantines=())
        evidence = SimpleNamespace(origin_integrity=True)
        report = SimpleNamespace(costs=SimpleNamespace(project_total=0))
        targets = (SimpleNamespace(comparison=SimpleNamespace(byte_exact=True)),)

        @staticmethod
        def accepts(_policy: object) -> bool:
            return True

    def verify_run(_engine: object, request: object) -> FakeVerificationResult:
        assert request.cold is True  # type: ignore[attr-defined]
        cold_requests.append(request.cold)  # type: ignore[attr-defined]
        return FakeVerificationResult()

    monkeypatch.setattr("reprobit.cache.IncrementalCache", CacheBomb)
    monkeypatch.setattr("reprobit.cli._prepare_producer_graph_run", prepare)
    monkeypatch.setattr("reprobit.engine.ReproductionEngine.run", verify_run)
    monkeypatch.setattr("reprobit.legacy.bind_pe32_oracle", lambda _oracle: object())

    reference = project / "reference" / "program.bin"
    reference.unlink()
    assert main(["build", str(project), "--cold"]) == 0
    capsys.readouterr()
    reference.write_bytes(b"expected")
    # Verification is unconditionally cold even without spelling ``--cold``.
    assert main(["verify", str(project)]) == 0
    capsys.readouterr()

    assert cold_requests == [True, True]
    assert prepared_calls == ["prepared", "prepared"]
    assert bound_legacy_targets == [frozenset(), frozenset()]
    assert not (project / ".reprobit-state" / "cache").exists()


def test_plain_build_loads_worktree_authority_before_state_and_emits_warm_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from reprobit.execution import BuildExecutionReceipt, FileReceipt

    project = tmp_path / "project"
    _initialize(project)
    capsys.readouterr()
    spec = load_project(project)
    bundle = SimpleNamespace(spec=spec)
    authority = SimpleNamespace(bundle=bundle)
    toolchain = tmp_path / "toolchain"
    toolchain.mkdir()
    order: list[str] = []

    def load(
        _root: Path,
        *,
        verify_source_authority: bool = True,
    ) -> SimpleNamespace:
        order.append(f"load:{verify_source_authority}")
        assert verify_source_authority is False
        assert not (project / spec.state_dir).exists()
        return bundle

    def worktree(current: object, root: Path) -> SimpleNamespace:
        assert current is bundle and root == project.resolve()
        order.append("worktree")
        assert not (project / spec.state_dir).exists()
        return authority

    def execute(current: object, **kwargs: object) -> SimpleNamespace:
        assert current is authority
        order.append("execute")
        state_root = kwargs["state_root"]
        assert isinstance(state_root, Path) and state_root.is_dir()
        target = project / spec.targets[0].artifact
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"warm")
        return SimpleNamespace(
            receipt=BuildExecutionReceipt(
                False,
                (),
                (
                    FileReceipt(
                        target,
                        Digest.from_bytes(b"warm"),
                        len(b"warm"),
                        True,
                    ),
                ),
                (),
            ),
            summary=IncrementalBuildSummary(
                producer_hits=4,
                producer_misses=0,
                transform_hits=1,
                transform_misses=0,
                elapsed_seconds=0.25,
                runtime_init_count=0,
            ),
        )

    monkeypatch.setattr("reprobit.cli.load_project_tree", load)
    monkeypatch.setattr("reprobit.incremental.current_worktree_authority", worktree)
    monkeypatch.setattr("reprobit.classic_incremental.execute_classic_incremental_build", execute)
    monkeypatch.setattr("reprobit.cli._selected_backend", lambda _args: object())

    assert (
        main(
            [
                "--format",
                "ndjson",
                "build",
                str(project),
                "--toolchain-root",
                str(toolchain),
                "--keep-workspace",
                "never",
            ]
        )
        == 0
    )
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    summary = next(event for event in events if event["event"] == "incremental_build_summary")
    assert summary["hits"] == 5
    assert summary["misses"] == 0
    assert summary["runtime_init_count"] == 0
    completion = next(event for event in events if event["event"] == "build_complete")
    assert completion["nodes"] == 5
    assert "0 step" not in completion["message"]
    assert order == ["load:False", "worktree", "execute"]


def test_verify_policy_override_can_narrow_but_never_broaden(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = tmp_path / "project"
    _complete_project(project, command_build=True)
    capsys.readouterr()

    assert (
        main(
            [
                "verify",
                str(project),
                "--policy",
                "allow-quarantine",
            ]
        )
        == 2
    )
    assert "would broaden the committed clean policy" in capsys.readouterr().err

    project_file = project / "reprobit.toml"
    project_file.write_text(
        project_file.read_text(encoding="utf-8").replace(
            'policy = "clean"', 'policy = "allow-quarantine"'
        ),
        encoding="utf-8",
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
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert main(["verify", str(project), "--policy", "clean"]) == 2
    assert "refuses command adapters" in capsys.readouterr().err


def test_verify_rejects_redundant_cold_profile_and_individual_report_flags(
    capsys: pytest.CaptureFixture[str],
) -> None:
    for option in ("--cold", "--toolchain-profile", "--report-json", "--report-html"):
        with pytest.raises(SystemExit) as raised:
            main(["verify", option, "unused"])
        assert raised.value.code == 2
        assert "unrecognized arguments" in capsys.readouterr().err


def test_manifest_preview_and_apply_use_the_cas_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source_project = tmp_path / "source-project"
    _complete_project(source_project)
    capsys.readouterr()
    files = _migration_files(source_project)
    legacy = tmp_path / "legacy.json"
    legacy.write_text('{"schema":2}')
    claims = tmp_path / "claims.json"
    claims.write_text('{"schema":1,"bindings":[]}')
    result = MigrationOutput(files, "a" * 64, 1, 0)
    seen_claims: list[Path | None] = []

    def migrate(
        path: Path,
        *,
        semantic_claims_path: Path | None = None,
    ) -> MigrationOutput:
        seen_claims.append(semantic_claims_path)
        return result

    monkeypatch.setattr("reprobit.migration.migration_output", migrate)
    destination = tmp_path / "destination"
    destination.mkdir()
    stale_intervention = (
        destination / "reprobit/interventions/tus/program--tu_ffffffffffffffff.json"
    )
    stale_proof = destination / "reprobit/proofs/tus/program--tu_ffffffffffffffff.json"
    stale_intervention.parent.mkdir(parents=True)
    stale_proof.parent.mkdir(parents=True)
    extra_intervention = json.loads(files[PurePosixPath("reprobit/interventions/program.json")])
    extra_intervention["interventions"][0]["id"] = "state.extra"
    extra_intervention["interventions"][0]["carrier"] = "state.extra.carrier"
    stale_intervention.write_bytes(canonical_json(extra_intervention))
    stale_proof.write_bytes(files[PurePosixPath("reprobit/proofs/program.proof.json")])
    stale_graph = destination / "reprobit/producer-graph.json"
    stale_graph.write_bytes(
        canonical_json(
            ProducerGraphDocument(
                schema_version=2,
                source_topology_digest=Digest.from_bytes(b"stale source topology"),
                toolchain_lock_digest=Digest.from_bytes(b"stale toolchain"),
                path_profile_id="dos-stable-v1",
                extractor="cmake-unix-makefiles-v1",
                nodes=(
                    ProducerNode(
                        id="compiler.stale",
                        role=ProducerRole.COMPILER,
                        owner="program",
                        arguments=("/c",),
                        outputs=("build/stale.obj",),
                    ),
                ),
            )
        )
    )
    arbitrary = destination / "reprobit/interventions/tus/keep-me.txt"
    arbitrary.write_text("not a ReproBit schema file", encoding="utf-8")
    preserved_paths = (stale_intervention, stale_proof)

    assert (
        main(
            [
                "manifest",
                "migrate",
                str(legacy),
                "--project-root",
                str(destination),
                "--semantic-claims",
                str(claims),
            ]
        )
        == 0
    )
    preview = capsys.readouterr().out
    assert "1 managed removal(s)" in preview
    assert stale_graph.relative_to(destination).as_posix() in preview
    assert all(
        f"preserve {path.relative_to(destination).as_posix()}" in preview
        for path in preserved_paths
    )
    assert all(path.is_file() for path in (*preserved_paths, stale_graph))
    assert not (destination / "reprobit.toml").exists()
    assert (
        main(
            [
                "manifest",
                "migrate",
                str(legacy),
                "--project-root",
                str(destination),
                "--semantic-claims",
                str(claims),
                "--apply",
            ]
        )
        == 0
    )
    applied = capsys.readouterr().out
    assert "1 managed removal(s)" in applied
    assert seen_claims == [claims.resolve(), claims.resolve()]
    assert not stale_graph.exists()
    assert all(path.is_file() for path in preserved_paths)
    assert arbitrary.read_text(encoding="utf-8") == "not a ReproBit schema file"
    loaded = load_project_tree(destination)
    assert loaded.spec.project_id == "sample"
    assert any(item.id == "state.extra" for item in loaded.interventions)


def test_report_help_explains_the_input_and_output_paths(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["report", "--help"])

    assert stopped.value.code == 0
    help_text = capsys.readouterr().out
    assert "canonical report.json to validate and render" in help_text
    assert "replace the input suffix with .html" in help_text


def test_primary_help_uses_human_terms_for_common_workflows(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["--help"])

    assert stopped.value.code == 0
    top_level = " ".join(capsys.readouterr().out.split())
    assert "review and lock the source files a build may read" in top_level
    assert "check exact bytes and trust evidence" in top_level
    assert "save only proven results" in top_level
    assert "portable project read set" not in top_level
    assert "cold exact solution" not in top_level


def test_report_and_cmake_module_commands(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = tmp_path / "project"
    _complete_project(project)
    bundle = load_project_tree(project)
    component_digest = Digest.from_bytes(b"fixture component")
    target = bundle.spec.targets[0]
    target_digest = Digest.from_bytes(b"expected")
    step_id = "build.program"
    runtime = RuntimeProofBinding.create(
        RuntimeBindingPreimage(
            build=BuildExecutionSummary(
                cold=True,
                inputs=(),
                outputs=(
                    ExecutionFileReceipt(
                        path=target.artifact,
                        digest=target_digest,
                        size=len(b"expected"),
                        fresh=True,
                        producer_step=step_id,
                        device=1,
                        inode=1,
                    ),
                ),
                steps=(
                    ExecutionStepReceipt(
                        id=step_id,
                        returncode=0,
                        attempts=1,
                        duration_seconds=0,
                        output_digest=Digest.from_bytes(b"step output"),
                        command_digest=Digest.from_bytes(b"step command"),
                    ),
                ),
            ),
            targets=(
                TargetComparisonSummary(
                    id=target.id,
                    logical_artifact=target.artifact,
                    artifact=target.artifact,
                    candidate_digest=target_digest,
                    candidate_size=len(b"expected"),
                    oracle_digest=target_digest,
                    oracle_size=len(b"expected"),
                    byte_exact=True,
                    candidate_device=1,
                    candidate_inode=1,
                ),
            ),
        )
    )
    tool = bundle.toolchain_lock.tools[0]
    artifact = Artifact(
        id="program.image",
        kind=ArtifactKind.IMAGE,
        logical_path=target.artifact,
        digest=target_digest,
        size=len(b"expected"),
        origin=ArtifactOrigin.FRESH_SEED,
        producer=tool.id,
    )
    proof = ProofReport.create(
        runtime=runtime,
        artifacts=(artifact,),
        provenance=(
            ProvenanceNode(
                id="program.origin",
                kind=ProvenanceKind.PRODUCER,
                operation="link",
                origin=ArtifactOrigin.FRESH_SEED,
                artifact_id=artifact.id,
            ),
        ),
        certificates=(),
        producers=(
            ProducerSummary(
                id="producer.program",
                artifact_id=artifact.id,
                step_id=step_id,
                producer_kind="linker",
                tool_id=tool.id,
                tool_digest=tool.digest,
                artifact_digest=artifact.digest,
                artifact_size=artifact.size,
            ),
        ),
        audit_issues=(),
        adapter=ComponentIdentity(
            role="adapter",
            id="fixture-adapter",
            implementation="fixture.Adapter",
            package="fixture",
            version="1",
            digest=component_digest,
        ),
        providers=(),
        package=ComponentIdentity(
            role="package",
            id="fixture",
            implementation="fixture",
            package="fixture",
            version="1",
            digest=component_digest,
        ),
    )
    report = Report.from_bundle(
        bundle,
        Verdict(
            cold=True,
            byte_exact=True,
            logic_certified=True,
            toolchain_origin=True,
        ),
        evidence=proof.summary,
        proof=proof,
        target_results={"program": True},
        target_artifacts={"program": (len(b"expected"), target_digest)},
    )
    report_json = tmp_path / "report.json"
    write_report_json(report, report_json)
    report_html = tmp_path / "report.html"

    assert main(["report", str(report_json), "--html", str(report_html)]) == 0
    assert "<!doctype html>" in report_html.read_text()
    assert main(["cmake-module", "--file"]) == 0
    module = Path(capsys.readouterr().out.strip().splitlines()[-1])
    assert module.name == "ReproBit.cmake" and module.is_file()
