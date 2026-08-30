"""Classic MSVC intervention dispatch and effective-workspace materialization.

Certifying execution consumes committed producer graphs in :mod:`classic_runtime`.
This module retains project-neutral intervention dispatch plus the sealed
source/CMake materialization used by cold execution and graph extraction.
Candidate producers never receive verification oracle bytes.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any

import reprobit.classic.composition as composition
import reprobit.classic.pe_imports as pe_imports
import reprobit.classic.pe_metadata as pe_metadata
import reprobit.classic.pe_rdata as pe_rdata
import reprobit.classic.pe_text as pe_text
import reprobit.classic.registers as registers
import reprobit.classic.rewriting as rewriting
import reprobit.classic.scheduling as scheduling
from reprobit.classic.compiler_identity import Msvc420CompilerIdentity
from reprobit.classic.semantic_contracts import (
    _CLASSIC_SEMANTIC_ISSUER,
    _ClassicCandidateSemanticMaterial,
    issue_classic_candidate_semantics,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest, SemanticProof
from reprobit.schema import (
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    ProjectBundle,
)
from reprobit.secure_path_contracts import SecurePathError
from reprobit.secure_paths import (
    atomic_publish_relative,
    read_relative_file,
)
from reprobit.strict_json import canonical_json


@dataclass(frozen=True, slots=True)
class OverlayOutputWitness:
    """Fresh receipt for one rendered project-overlay output."""

    path: str
    input_digest: str
    output_digest: str
    operation_count: int


class ClassicProjectError(RuntimeError):
    """A project cannot be executed without guessing or stale state."""


class FamilyExecutionMode(StrEnum):
    SOURCE_OVERLAY = "source-overlay"
    DONOR_COMPILE = "donor-compile"
    CLEAN_CANDIDATE = "clean-candidate"
    LINK_OR_POSTLINK = "link-or-postlink"
    QUARANTINE_ONLY = "quarantine-only"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class FamilyCoverage:
    mode: FamilyExecutionMode
    implemented: bool
    detail: str


def _coverage() -> Mapping[ClassicRecipeFamily, FamilyCoverage]:
    donor = {
        ClassicRecipeFamily.DECLARATION_SHAPE,
        ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        ClassicRecipeFamily.FORWARD_DECLARATION_RUN,
        ClassicRecipeFamily.PAD_SHAPE,
        ClassicRecipeFamily.EXTERN_RUN_PAIR,
        ClassicRecipeFamily.FORWARD_RUN_WITH_SHAPE,
        ClassicRecipeFamily.DECLARATION_RUN_TRIPLE,
        ClassicRecipeFamily.PREFIX_FORWARD_AFTER_INCLUDES_EXTERN,
    }
    candidate = {
        ClassicRecipeFamily.EQUAL_BODY_STRICT,
        ClassicRecipeFamily.EQUAL_BODY_EH_STRUCTURAL_LOCAL,
        ClassicRecipeFamily.SAME_SLOT_RESIZE,
        ClassicRecipeFamily.EQUAL_BODY_EH_RELOC_LAYOUT,
        ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT,
        ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING,
        ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC,
        ClassicRecipeFamily.RETAIL_EXACT_REGISTER_BIJECTION,
        ClassicRecipeFamily.RETAIL_EXACT_SOURCE_EQUAL_BODY,
        ClassicRecipeFamily.RETAIL_EXACT_COMPOSED_REWRITING,
        ClassicRecipeFamily.RETAIL_EXACT_WEB_RECOLOUR,
        ClassicRecipeFamily.RETAIL_EXACT_CROSS_TU_COMPLETE_TARGET_RESIZE,
        ClassicRecipeFamily.RETAIL_EXACT_REGISTER_BIJECTION_REENCODING,
        ClassicRecipeFamily.RETAIL_EXACT_SAME_TU_INSTRUCTION_HYBRID_RESIZE,
        ClassicRecipeFamily.RETAIL_EXACT_SOURCE_TARGET_CLOSURE,
    }
    result: dict[ClassicRecipeFamily, FamilyCoverage] = {}
    for family in ClassicRecipeFamily:
        if family is ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH:
            result[family] = FamilyCoverage(
                FamilyExecutionMode.SOURCE_OVERLAY,
                True,
                "pinned source copy plus closed declarative generators; opaque legacy anchors fail",
            )
        elif family in donor:
            result[family] = FamilyCoverage(
                FamilyExecutionMode.DONOR_COMPILE,
                False,
                "compile-lane plumbing exists, but this donor source family is not yet rendered",
            )
        elif family in candidate:
            result[family] = FamilyCoverage(
                FamilyExecutionMode.CLEAN_CANDIDATE,
                True,
                "oracle-free classic candidate producer is dispatchable",
            )
        elif family is ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION:
            result[family] = FamilyCoverage(
                FamilyExecutionMode.QUARANTINE_ONLY,
                False,
                "must be represented and executed by the quarantined simulated-elision composer",
            )
        elif family in {
            ClassicRecipeFamily.IMAGE_BINARY_REPACK,
            ClassicRecipeFamily.IMAGE_METADATA,
            ClassicRecipeFamily.IMAGE_LINK_ORDER,
        }:
            result[family] = FamilyCoverage(
                FamilyExecutionMode.LINK_OR_POSTLINK,
                True,
                "closed candidate-only terminal declaration is dispatchable",
            )
        else:
            result[family] = FamilyCoverage(
                FamilyExecutionMode.LINK_OR_POSTLINK,
                False,
                "typed declaration is preserved but the terminal producer is not implemented",
            )
    if set(result) != set(ClassicRecipeFamily):
        raise AssertionError("classic family coverage is not exhaustive")
    return MappingProxyType(result)


FAMILY_COVERAGE = _coverage()


@dataclass(frozen=True, slots=True)
class ClassicDispatchMaterials:
    """Fresh compiler products supplied to an oracle-free classic producer."""

    seed_object: bytes
    donor_object: bytes | None = None
    target_donor_object: bytes | None = None
    complete_donor_object: bytes | None = None
    instruction_donor_object: bytes | None = None
    seed_source: bytes | None = None
    donor_source: bytes | None = None
    target_donor_source: bytes | None = None
    instruction_donor_source: bytes | None = None
    additional_donor_objects: Mapping[str, bytes] = field(default_factory=dict)
    shape_identifiers: frozenset[str] = frozenset()
    candidate_constraints: Mapping[str, object] | None = None
    compiler_identity: Msvc420CompilerIdentity | None = None


@dataclass(frozen=True, slots=True)
class ClassicCandidate:
    output: bytes
    proof: Mapping[str, object]
    evidence_digest: Digest
    semantic_proof: SemanticProof
    semantic_input_statement: Mapping[str, object]
    semantic_output_statement: Mapping[str, object]


def _required_bytes(value: bytes | None, label: str) -> bytes:
    if value is None:
        raise ClassicProjectError(f"classic producer requires fresh {label}")
    return value


def _present_bytes(**values: bytes | None) -> dict[str, bytes]:
    return {name: value for name, value in values.items() if value is not None}


class ClassicFamilyDispatcher:
    """Typed dispatcher; no verifier or oracle object crosses this seam."""

    def dispatch(
        self,
        intervention: ClassicRecipeIntervention,
        materials: ClassicDispatchMaterials,
    ) -> ClassicCandidate:
        if intervention.role is not ClassicRecipeRole.FUNCTION:
            raise ClassicProjectError("only function recipes produce binary candidates")
        coverage = FAMILY_COVERAGE[intervention.family]
        if coverage.mode is not FamilyExecutionMode.CLEAN_CANDIDATE or not coverage.implemented:
            raise ClassicProjectError(
                f"classic family {intervention.family.value!r} is not a clean candidate: "
                f"{coverage.detail}"
            )
        function: dict[str, Any] = (
            dict(materials.candidate_constraints)
            if materials.candidate_constraints is not None
            else {item.name: item.value for item in intervention.parameters}
        )
        declared_splice = function.setdefault("splice_class", intervention.family.value)
        if declared_splice != intervention.family.value:
            raise ClassicProjectError("candidate splice class differs from the typed recipe family")
        declared_symbol = function.get("symbol")
        declared_mangled = function.get("mangled")
        if declared_symbol not in {None, intervention.symbol} or declared_mangled not in {
            None,
            intervention.symbol,
        }:
            raise ClassicProjectError("candidate symbol differs from the typed recipe scope")
        function["kind"] = intervention.family.value
        function["symbol"] = intervention.symbol
        # The low-level, payload-free classic producers retain the v2 field
        # name internally.  The value itself comes only from typed schema-v3
        # authority at this adapter seam.
        function["mangled"] = intervention.symbol
        seed = materials.seed_object
        donor = _required_bytes(materials.donor_object, "donor object")
        family = intervention.family
        if family in {
            ClassicRecipeFamily.EQUAL_BODY_STRICT,
            ClassicRecipeFamily.EQUAL_BODY_EH_STRUCTURAL_LOCAL,
            ClassicRecipeFamily.EQUAL_BODY_EH_RELOC_LAYOUT,
        }:
            output, proof = composition.compose_equal_body_comdat(seed, donor, function)
        elif family is ClassicRecipeFamily.SAME_SLOT_RESIZE:
            output, proof = composition.compose_same_slot_resize(seed, donor, function)
        elif family is ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT:
            if "target_source_refactor" in function:
                output, proof = composition.produce_source_refactor_candidate(
                    seed,
                    donor,
                    function,
                    _required_bytes(materials.seed_source, "seed source"),
                    _required_bytes(materials.donor_source, "donor source"),
                )
            else:
                output, proof = composition.produce_reloc_divergent_candidate(seed, donor, function)
        elif family is ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING:
            output, proof = rewriting.produce_donor_rewriting_candidate(
                seed, donor, function, compiler_identity=materials.compiler_identity
            )
        elif family is ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC:
            if "target_source_refactor" in function:
                output, proof = composition.produce_source_instruction_mosaic_candidate(
                    seed,
                    donor,
                    function,
                    _required_bytes(materials.seed_source, "seed source"),
                    _required_bytes(materials.donor_source, "donor source"),
                    dict(materials.additional_donor_objects),
                    primary_donor_id=intervention.dependencies[0],
                )
            else:
                output, proof = composition.produce_instruction_mosaic_candidate(
                    seed,
                    donor,
                    function,
                    dict(materials.additional_donor_objects),
                    primary_donor_id=intervention.dependencies[0],
                )
        elif family is ClassicRecipeFamily.RETAIL_EXACT_REGISTER_BIJECTION:
            output, proof = registers.produce_register_bijection_candidate(seed, donor, function)
        elif family is ClassicRecipeFamily.RETAIL_EXACT_SOURCE_EQUAL_BODY:
            output, proof = composition.produce_source_equal_body_candidate(
                seed,
                donor,
                function,
                _required_bytes(materials.seed_source, "seed source"),
                _required_bytes(materials.donor_source, "donor source"),
            )
        elif family is ClassicRecipeFamily.RETAIL_EXACT_COMPOSED_REWRITING:
            output, proof = rewriting.produce_composed_rewriting_candidate(
                seed, donor, function, compiler_identity=materials.compiler_identity
            )
        elif family is ClassicRecipeFamily.RETAIL_EXACT_WEB_RECOLOUR:
            output, proof = scheduling.produce_web_recolour_candidate(
                seed, donor, function, compiler_identity=materials.compiler_identity
            )
        elif family is ClassicRecipeFamily.RETAIL_EXACT_CROSS_TU_COMPLETE_TARGET_RESIZE:
            output, proof = composition.produce_cross_tu_complete_target_resize_candidate(
                seed,
                _required_bytes(materials.target_donor_object, "target donor object"),
                _required_bytes(materials.complete_donor_object, "complete donor object"),
                function,
            )
        elif family is ClassicRecipeFamily.RETAIL_EXACT_REGISTER_BIJECTION_REENCODING:
            output, proof = registers.produce_register_bijection_reencoding_candidate(
                seed, donor, function
            )
        elif family is ClassicRecipeFamily.RETAIL_EXACT_SAME_TU_INSTRUCTION_HYBRID_RESIZE:
            output, proof = composition.produce_same_tu_instruction_hybrid_resize_candidate(
                seed,
                _required_bytes(materials.target_donor_object, "target donor object"),
                _required_bytes(materials.instruction_donor_object, "instruction donor object"),
                function,
                _required_bytes(materials.seed_source, "seed source"),
                _required_bytes(materials.target_donor_source, "target donor source"),
                _required_bytes(materials.instruction_donor_source, "instruction donor source"),
            )
        elif family is ClassicRecipeFamily.RETAIL_EXACT_SOURCE_TARGET_CLOSURE:
            output, proof = composition.produce_source_target_closure_candidate(
                seed,
                donor,
                function,
                _required_bytes(materials.seed_source, "seed source"),
                _required_bytes(materials.donor_source, "donor source"),
            )
        else:  # Coverage and dispatch must evolve together.
            raise ClassicProjectError(f"classic family has no dispatcher: {family.value}")
        if not isinstance(output, bytes) or not isinstance(proof, Mapping):
            raise ClassicProjectError("classic producer returned a malformed candidate")
        proof_value = dict(proof)
        binary_inputs = {
            f"dependency:{intervention.dependencies[0]}": donor,
            **_present_bytes(
                target_donor_object=materials.target_donor_object,
                complete_donor_object=materials.complete_donor_object,
                instruction_donor_object=materials.instruction_donor_object,
            ),
            **{
                f"additional_donor:{name}": payload
                for name, payload in materials.additional_donor_objects.items()
            },
        }
        source_inputs = _present_bytes(
            seed_source=materials.seed_source,
            donor_source=materials.donor_source,
            target_donor_source=materials.target_donor_source,
            instruction_donor_source=materials.instruction_donor_source,
        )
        try:
            semantics = issue_classic_candidate_semantics(
                intervention,
                material=_ClassicCandidateSemanticMaterial(
                    intervention=intervention,
                    seed_input=seed,
                    binary_inputs=binary_inputs,
                    source_inputs=source_inputs,
                    candidate_constraints=function,
                    output=output,
                    validator_trace=proof_value,
                    _issuer=_CLASSIC_SEMANTIC_ISSUER,
                ),
            )
        except ClassicSemanticError as exc:
            raise ClassicProjectError(
                f"classic semantic validator rejected {intervention.id!r}: {exc}"
            ) from exc
        return ClassicCandidate(
            output,
            MappingProxyType(proof_value),
            Digest.from_bytes(canonical_json(proof_value)),
            semantics.proof,
            semantics.input_statement,
            semantics.output_statement,
        )

    def dispatch_project(
        self,
        intervention: ClassicRecipeIntervention,
        candidate: bytes,
        *,
        candidate_constraints: Mapping[str, object] | None = None,
    ) -> ClassicCandidate:
        """Apply one closed postlink transform to a freshly linked candidate."""

        if intervention.role is not ClassicRecipeRole.PROJECT:
            raise ClassicProjectError("project dispatcher accepts only project recipes")
        values = (
            dict(candidate_constraints)
            if candidate_constraints is not None
            else {item.name: item.value for item in intervention.parameters}
        )
        if intervention.family is ClassicRecipeFamily.IMAGE_METADATA:
            if set(values) != {"link_time", "resource_time"}:
                raise ClassicProjectError("image metadata declaration is not closed")
            output, proof = pe_metadata.apply_pe_metadata_candidate(candidate, values)
        elif intervention.family is ClassicRecipeFamily.IMAGE_LINK_ORDER:
            declaration: object = values.get("import_order")
            if (
                not isinstance(declaration, dict)
                or declaration.get("schema") != ("pe32_import_order_v1")
                or set(values) != {"import_order"}
            ):
                raise ClassicProjectError(
                    "image link-order recipe requires a closed pe32_import_order_v1 declaration"
                )
            output, proof = pe_imports.apply_pe_import_order_candidate(candidate, declaration)
        elif (
            intervention.family is ClassicRecipeFamily.IMAGE_BINARY_REPACK
            and set(values) == {"text_repack"}
            and isinstance(values["text_repack"], dict)
        ):
            declaration = values["text_repack"]
            if declaration.get("schema") != "comdat_tail_thunk_repack_v1":
                raise ClassicProjectError("unsupported text repack schema")
            output, proof = pe_text.apply_text_repack_candidate(candidate, declaration)
        elif (
            intervention.family is ClassicRecipeFamily.IMAGE_BINARY_REPACK
            and set(values) == {"rdata_pool_repack"}
            and isinstance(values["rdata_pool_repack"], dict)
        ):
            declaration = values["rdata_pool_repack"]
            if declaration.get("schema") != "rdata_pool_repack_v1":
                raise ClassicProjectError("unsupported rdata repack schema")
            output, proof = pe_rdata.apply_rdata_pool_repack_candidate(candidate, declaration)
        else:
            raise ClassicProjectError("image repack declaration is not closed or unambiguous")
        if not isinstance(output, bytes) or not isinstance(proof, Mapping):
            raise ClassicProjectError("classic project producer returned malformed evidence")
        proof_value = dict(proof)
        if (
            proof_value.get("candidate_only") is not True
            or proof_value.get("oracle_payload_bytes_read") != 0
        ):
            raise ClassicProjectError("classic project producer violated candidate-only policy")
        try:
            semantics = issue_classic_candidate_semantics(
                intervention,
                material=_ClassicCandidateSemanticMaterial(
                    intervention=intervention,
                    seed_input=candidate,
                    binary_inputs={},
                    source_inputs={},
                    candidate_constraints=values,
                    output=output,
                    validator_trace=proof_value,
                    _issuer=_CLASSIC_SEMANTIC_ISSUER,
                ),
            )
        except ClassicSemanticError as exc:
            raise ClassicProjectError(
                f"classic semantic validator rejected {intervention.id!r}: {exc}"
            ) from exc
        return ClassicCandidate(
            output,
            MappingProxyType(proof_value),
            Digest.from_bytes(canonical_json(proof_value)),
            semantics.proof,
            semantics.input_statement,
            semantics.output_statement,
        )


@dataclass(frozen=True, slots=True)
class InterventionWitness:
    intervention_id: str
    target_id: str
    evidence_digest: Digest
    legacy_oracle_install: bool = False
    semantic_proof: SemanticProof | None = None
    semantic_input_statement: Mapping[str, object] | None = None
    semantic_output_statement: Mapping[str, object] | None = None
    output_digest: Digest | None = None
    output_size: int | None = None


def _relative_path(value: str) -> str:
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ClassicProjectError(f"project path is unsafe: {value!r}")
    return path.as_posix()


def _digest_path(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parameter_map(intervention: ClassicRecipeIntervention) -> dict[str, Any]:
    return {item.name: item.value for item in intervention.parameters}


def _copy_effective_source(
    source_root: Path,
    destination: Path,
    *,
    bundle: ProjectBundle,
) -> None:
    source_root = source_root.resolve(strict=True)
    destination = destination.absolute()
    manifest = bundle.source_manifest
    if manifest is None or not manifest.complete:
        raise ClassicProjectError("classic execution requires a complete source manifest")
    if destination.is_symlink() or (
        destination.exists() and (not destination.is_dir() or any(destination.iterdir()))
    ):
        raise ClassicProjectError(f"effective workspace is not empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    destination = destination.resolve(strict=True)
    for entry in manifest.entries:
        try:
            payload, source_receipt = read_relative_file(source_root, entry.path)
        except SecurePathError as exc:
            raise ClassicProjectError(
                f"source input cannot be read without redirection: {entry.path!r}"
            ) from exc
        if source_receipt.size != entry.size or source_receipt.digest != entry.digest:
            raise ClassicProjectError(
                f"source input differs from portable manifest: {entry.path!r}"
            )
        try:
            target_receipt = atomic_publish_relative(destination, entry.path, payload)
        except SecurePathError as exc:
            raise ClassicProjectError(
                f"effective source copy cannot be published safely: {entry.path!r}"
            ) from exc
        if target_receipt.size != entry.size or target_receipt.digest != entry.digest:
            raise ClassicProjectError(f"effective source copy differs from receipt: {entry.path!r}")


def _effective_source_seal(root: Path) -> tuple[tuple[str, int, str], ...]:
    """Receipt every effective input and reject redirects in the closed tree."""

    root = root.resolve(strict=True)
    values: list[tuple[str, int, str]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().casefold()):
        if path.is_symlink():
            raise ClassicProjectError(f"effective source contains a symlink: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        values.append((relative, path.stat().st_size, _digest_path(path)))
    folded = [item[0].casefold() for item in values]
    if len(folded) != len(set(folded)):
        raise ClassicProjectError("effective source contains DOS-case-colliding paths")
    return tuple(values)


def materialize_effective_workspace(
    bundle: ProjectBundle,
    project_root: Path,
    destination: Path,
) -> tuple[InterventionWitness, ...]:
    """Copy oracle-free project inputs and render authoritative overlay shards."""
    project_root = project_root.resolve(strict=True)
    if project_root != Path(bundle.root).resolve(strict=True):
        raise ClassicProjectError("adapter project root differs from loaded bundle")
    oracle_paths = tuple(
        (project_root / target.oracle).resolve(strict=False) for target in bundle.spec.targets
    )
    _copy_effective_source(
        project_root,
        destination,
        bundle=bundle,
    )
    overlay_witnesses: list[OverlayOutputWitness] = []
    intervention_witnesses: list[InterventionWitness] = []
    forbidden_outputs = {
        path.relative_to(project_root).as_posix().casefold() for path in oracle_paths
    }
    for intervention in bundle.interventions:
        if not isinstance(intervention, ClassicRecipeIntervention):
            continue
        if intervention.family is not ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH:
            continue
        values = _parameter_map(intervention)
        outputs = values.get("outputs")
        graph = values.get("graph")
        schema = values.get("schema")
        if not isinstance(outputs, list) or not isinstance(graph, dict) or schema != 2:
            raise ClassicProjectError("source-overlay declaration is malformed")
        clean_inputs: dict[str, bytes] = {}
        for raw in outputs:
            if not isinstance(raw, dict):
                raise ClassicProjectError("source-overlay output must be an object")
            relative = _relative_path(str(raw.get("path", "")))
            if relative.casefold() in forbidden_outputs:
                raise ClassicProjectError("source overlay cannot write a verification oracle")
            path = destination.joinpath(*PurePosixPath(relative).parts)
            try:
                path.resolve(strict=False).relative_to(destination.resolve(strict=True))
            except ValueError as exc:
                raise ClassicProjectError(
                    "source-overlay output escapes effective workspace"
                ) from exc
            if "clean" in raw:
                if not path.is_file():
                    raise ClassicProjectError(f"overlay clean input is absent: {relative}")
                clean_inputs[relative] = path.read_bytes()
        try:
            from reprobit.classic_overlay_document import render_classic_overlay

            rendered = render_classic_overlay(
                {"schema": schema, "outputs": outputs, "graph": graph},
                clean_inputs,
            )
        except ValueError as exc:
            raise ClassicProjectError(f"cannot render overlay {intervention.id!r}: {exc}") from exc
        current: list[OverlayOutputWitness] = []
        for receipt in rendered.receipts:
            relative = receipt.path
            path = destination.joinpath(*PurePosixPath(relative).parts)
            output = rendered.outputs[relative]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(output)
            witness = OverlayOutputWitness(
                relative,
                receipt.input_digest or sha256(b"").hexdigest(),
                receipt.output_digest,
                len(receipt.operations),
            )
            current.append(witness)
            overlay_witnesses.append(witness)
        evidence = Digest.from_bytes(
            canonical_json(
                [
                    {
                        "path": item.path,
                        "input": item.input_digest,
                        "output": item.output_digest,
                        "operations": item.operation_count,
                    }
                    for item in current
                ]
            )
        )
        intervention_witnesses.append(
            InterventionWitness(intervention.id, intervention.scope.target, evidence)
        )
    if bundle.build_plan is not None:
        for unit in bundle.build_plan.translation_units:
            unit_source = destination.joinpath(*PurePosixPath(unit.source).parts)
            if not unit_source.is_file() or _digest_path(unit_source) != unit.source_digest.value:
                raise ClassicProjectError(f"effective source differs from TU pin: {unit.source!r}")
    manifest = bundle.source_manifest
    assert manifest is not None
    admitted = {item.path.casefold() for item in manifest.entries}
    admitted.update(item.path.casefold() for item in overlay_witnesses)
    received = {item[0].casefold() for item in _effective_source_seal(destination)}
    if received != admitted:
        missing = sorted(admitted - received)
        extra = sorted(received - admitted)
        raise ClassicProjectError(
            f"effective source differs from closed authority; missing={missing}, extra={extra}"
        )
    return tuple(intervention_witnesses)


def _cmake_quote(value: str) -> str:
    if any(character in value for character in ("\0", "\n", "\r", ";", "$", '"')):
        raise ClassicProjectError(f"value cannot be represented safely in CMake: {value!r}")
    return f'"{value}"'


def _cmake_effective_path(relative: str) -> str:
    # ``relative`` has already passed the strict project-relative path check.
    return f'"${{REPROBIT_EFFECTIVE_SOURCE_ROOT}}/{relative}"'


def write_cmake_project_plan(
    bundle: ProjectBundle,
    effective_root: Path,
    destination: Path,
) -> None:
    """Emit generic target-seat calls from authoritative overlay graph records."""

    lines = [
        "# Generated by ReproBit; do not edit.",
        "if(NOT DEFINED REPROBIT_EFFECTIVE_SOURCE_ROOT)",
        '  message(FATAL_ERROR "REPROBIT_EFFECTIVE_SOURCE_ROOT is required")',
        "endif()",
    ]
    for intervention in bundle.interventions:
        if not isinstance(intervention, ClassicRecipeIntervention) or (
            intervention.family is not ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
        ):
            continue
        values = _parameter_map(intervention)
        graph = values.get("graph")
        outputs = values.get("outputs")
        if not isinstance(graph, dict) or not isinstance(outputs, list):
            raise ClassicProjectError("source-overlay graph is malformed")
        pins = {
            _relative_path(str(item.get("path", ""))): item
            for item in outputs
            if isinstance(item, dict)
        }
        generated = graph.get("generated_tus", [])
        if not isinstance(generated, list):
            raise ClassicProjectError("generated_tus must be an array")
        generated_paths = {
            _relative_path(str(item.get("path", "")))
            for item in generated
            if isinstance(item, dict)
        }
        for item in generated:
            if not isinstance(item, dict):
                raise ClassicProjectError("generated TU seat must be an object")
            relative = _relative_path(str(item.get("path", "")))
            ordinal = item.get("ordinal")
            if type(ordinal) is not int or ordinal < 1 or relative not in pins:
                raise ClassicProjectError("generated TU lacks an output pin or ordinal")
            source = effective_root.joinpath(*PurePosixPath(relative).parts)
            if not source.is_file():
                raise ClassicProjectError(f"generated TU is absent: {relative}")
            arguments = [
                "  TARGET",
                _cmake_quote(intervention.build_target),
                "SOURCE",
                _cmake_effective_path(relative),
                "INDEX",
                str(ordinal - 1),
                "LANGUAGE",
                "C" if source.suffix.casefold() == ".c" else "CXX",
                "SHA256",
                _digest_path(source),
                "SIZE",
                str(source.stat().st_size),
            ]
            for label in ("after", "before"):
                neighbor = item.get(label)
                if neighbor is None:
                    continue
                neighbor_relative = _relative_path(str(neighbor))
                # A generated successor is inserted later at its own exact
                # ordinal and pins this item through its AFTER neighbour.
                # It cannot also be present for this earlier BEFORE check.
                if label == "before" and neighbor_relative in generated_paths:
                    continue
                neighbor_path = effective_root.joinpath(*PurePosixPath(neighbor_relative).parts)
                if not neighbor_path.is_file():
                    raise ClassicProjectError(f"generated TU neighbor is absent: {neighbor}")
                arguments.extend((label.upper(), _cmake_effective_path(neighbor_relative)))
            lines.extend(("reprobit_insert_generated_source(", " ".join(arguments), ")"))
    if bundle.build_plan is None:
        raise ClassicProjectError("CMake project plan requires build target gates")
    for gate in bundle.build_plan.target_gates:
        lines.extend(
            (
                "reprobit_register_target(",
                " ".join(
                    (
                        "  TARGET",
                        _cmake_quote(gate.build_target),
                        "ARTIFACT_ID",
                        _cmake_quote(gate.target_id),
                    )
                ),
                ")",
            )
        )
    lines.extend(
        (
            'if(NOT DEFINED REPROBIT_TARGET_PLAN OR REPROBIT_TARGET_PLAN STREQUAL "")',
            '  message(FATAL_ERROR "REPROBIT_TARGET_PLAN is required")',
            "endif()",
            'reprobit_write_plan(OUTPUT "${REPROBIT_TARGET_PLAN}")',
        )
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.replace(temporary, destination)


__all__ = [
    "FAMILY_COVERAGE",
    "ClassicCandidate",
    "ClassicDispatchMaterials",
    "ClassicFamilyDispatcher",
    "ClassicProjectError",
    "FamilyCoverage",
    "FamilyExecutionMode",
    "InterventionWitness",
    "materialize_effective_workspace",
    "write_cmake_project_plan",
]
