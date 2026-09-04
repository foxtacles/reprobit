"""Closed MSVC 4.20 compiler-state code-image projection coordinator."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from types import MappingProxyType

from reprobit.binary import ByteIdentityError
from reprobit.classic.compiler_identity import Msvc420CompilerIdentity
from reprobit.classic.debug import parse_fpo_data
from reprobit.classic.register_reencoding import (
    FPO_FRAME_KIND_FPO,
    require_no_ebp_frame_derivation,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest
from reprobit.strict_json import canonical_json

from .commutative import derive_commutative_operand_forms
from .compiler_state_eh import _SYNCHRONOUS_EXCEPTION_MODEL
from .compiler_state_foundation import (
    CompilerStateCodeCertificate,
    CompilerStateCodePair,
    CompilerStateCompilerEvidence,
    CompilerStateProjection,
    _ImageState,
    _Instruction,
    _instructions,
    _relocation_parts,
    _RelocationRecord,
    _require_relocation_semantics,
)
from .compiler_state_prologue import _try_saved_prologue_web_permutation
from .compiler_state_schedule import _apply_schedules
from .compiler_state_schedule_web import _try_atomic_schedule_register_web
from .compiler_state_web import _prove_register_web_recolour, _try_register_bijection
from .relational_projection import (
    derive_equality_compare_reversals,
    equality_compare_reversal_images,
    equality_compare_reversal_preimages,
)

_THEOREM = "msvc-4.20-compiler-state-code-image-v1"
_MAX_SOURCE_ALGEBRAIC_IMAGES = 15


def _try_commutative_operand_forms(
    state: _ImageState,
    pair: CompilerStateCodePair,
    source_records: Mapping[int, Mapping[str, object]],
) -> tuple[_ImageState, dict[str, object]] | None:
    """Prove a residual image of derived x87 commutative operand exchanges."""

    derived = derive_commutative_operand_forms(
        state.body,
        pair.effective_body,
        source_records,
        frozenset(pair.external_entries),
        f"MSVC 4.20 compiler-state commutative image {pair.owner!r}",
    )
    if derived is None:
        return None
    image, declaration, proof = derived
    if image != pair.effective_body:
        return None
    return _ImageState(image, list(state.relocation_offsets)), {
        "kind": "derived-x87-commutative-operand-form-v1",
        "declaration": declaration,
        "proof": proof,
        "debug_authority": "effective-compiler-product",
    }


def _try_equality_compare_reversals(
    state: _ImageState,
    pair: CompilerStateCodePair,
    source_records: Mapping[int, Mapping[str, object]],
) -> tuple[_ImageState, dict[str, object]] | None:
    """Prove a residual image made only of derived JE/JNE CMP reversals."""

    derived = derive_equality_compare_reversals(
        state.body,
        pair.effective_body,
        source_records,
        frozenset(pair.external_entries),
        f"MSVC 4.20 compiler-state relational image {pair.owner!r}",
    )
    if derived is None:
        return None
    image, declaration, proof = derived
    if image != pair.effective_body:
        return None
    return _ImageState(image, list(state.relocation_offsets)), {
        "kind": "derived-equality-compare-reversal-v1",
        "declaration": declaration,
        "proof": proof,
    }


def _try_algebraic_residual(
    state: _ImageState,
    pair: CompilerStateCodePair,
    source_records: Mapping[int, Mapping[str, object]],
) -> tuple[_ImageState, list[dict[str, object]]]:
    """Try the closed algebraic projections that can finish an exact image."""

    for projector in (_try_commutative_operand_forms, _try_equality_compare_reversals):
        projected = projector(state, pair, source_records)
        if projected is not None:
            image, proof = projected
            return image, [proof]
    return state, []


def _try_web_with_algebraic_residual(
    state: _ImageState,
    pair: CompilerStateCodePair,
    source_records: Mapping[int, _RelocationRecord],
    target_records: Mapping[int, _RelocationRecord],
    *,
    frame_pointer_free: bool,
) -> tuple[_ImageState, list[dict[str, object]]] | None:
    """Prove a register web through one uniquely rejoining algebraic preimage."""

    preimages = equality_compare_reversal_preimages(
        state.body,
        pair.effective_body,
        target_records,
        frozenset(pair.external_entries),
        f"MSVC 4.20 compiler-state algebraic bridge {pair.owner!r}",
    )
    candidates: list[tuple[_ImageState, list[dict[str, object]]]] = []
    for preimage in preimages:
        try:
            web_state, web_proof = _prove_register_web_recolour(
                state,
                replace(pair, effective_body=preimage),
                source_records,
                target_records,
                frame_pointer_free=frame_pointer_free,
            )
        except ClassicSemanticError:
            continue
        image, residual = _try_algebraic_residual(web_state, pair, source_records)
        if image.body == pair.effective_body:
            candidates.append((image, [web_proof, *residual]))
    if len(candidates) != 1:
        return None
    return candidates[0]


def _try_atomic_schedule_web_with_source_algebraic(
    state: _ImageState,
    pair: CompilerStateCodePair,
    source_records: Mapping[int, _RelocationRecord],
    target_records: Mapping[int, _RelocationRecord],
    compiler_identity: Msvc420CompilerIdentity | None,
) -> tuple[_ImageState, list[dict[str, object]]] | None:
    """Prove a unique atomic schedule/web, optionally after one equality image."""

    candidates: list[tuple[_ImageState, list[dict[str, object]]]] = []
    direct = _try_atomic_schedule_register_web(
        state,
        pair,
        source_records,
        target_records,
        compiler_identity,
    )
    if direct is not None:
        image, proof = direct
        return image, [proof]

    images = equality_compare_reversal_images(
        state.body,
        source_records,
        frozenset(pair.external_entries),
        f"MSVC 4.20 compiler-state source algebraic bridge {pair.owner!r}",
    )
    if len(images) > _MAX_SOURCE_ALGEBRAIC_IMAGES:
        return None
    for candidate_body in images:
        algebraic = _try_equality_compare_reversals(
            state,
            replace(pair, effective_body=candidate_body),
            source_records,
        )
        if algebraic is None:
            continue
        algebraic_state, algebraic_proof = algebraic
        fused = _try_atomic_schedule_register_web(
            algebraic_state,
            pair,
            source_records,
            target_records,
            compiler_identity,
        )
        if fused is None:
            continue
        image, fused_proof = fused
        candidates.append((image, [algebraic_proof, fused_proof]))
    if len(candidates) > 1:
        return None
    return candidates[0] if candidates else None


def _paired_frame_pointer_free_proof(
    pair: CompilerStateCodePair,
    clean_instructions: list[_Instruction],
    effective_instructions: list[_Instruction],
) -> dict[str, object] | None:
    evidence = pair.fpo_evidence
    if evidence is None:
        return None
    if (
        type(evidence.clean_body) is not bytes
        or not evidence.clean_body
        or type(evidence.effective_body) is not bytes
        or not evidence.effective_body
        or len(evidence.receipt_digest) != 64
        or any(character not in "0123456789abcdef" for character in evidence.receipt_digest)
    ):
        raise ClassicSemanticError("MSVC 4.20 compiler-state FPO evidence receipt is malformed")
    if len(pair.clean_body) != len(pair.effective_body):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state paired FPO evidence spans unequal code sizes"
        )
    try:
        clean_record = parse_fpo_data(evidence.clean_body, expected_proc_size=len(pair.clean_body))
        effective_record = parse_fpo_data(
            evidence.effective_body, expected_proc_size=len(pair.effective_body)
        )
    except ByteIdentityError as error:
        raise ClassicSemanticError(str(error)) from error
    if any(
        record["cbFrame"] != FPO_FRAME_KIND_FPO or record["fHasSEH"] != 0 or record["fUseBP"] != 1
        for record in (clean_record, effective_record)
    ):
        return None
    try:
        require_no_ebp_frame_derivation(
            pair.clean_body,
            clean_instructions,
            "MSVC 4.20 compiler-state clean FPO proof",
        )
        require_no_ebp_frame_derivation(
            pair.effective_body,
            effective_instructions,
            "MSVC 4.20 compiler-state effective FPO proof",
        )
    except ByteIdentityError:
        return None
    return {
        "kind": "paired-frame-pointer-free-evidence-v1",
        "receipt_digest": evidence.receipt_digest,
        "clean_record": clean_record,
        "effective_record": effective_record,
        "clean_body_digest": Digest.from_bytes(evidence.clean_body).value,
        "effective_body_digest": Digest.from_bytes(evidence.effective_body).value,
        "clean_instruction_count": len(clean_instructions),
        "effective_instruction_count": len(effective_instructions),
        "preserved": [
            "exact-paired-fpo-child-receipt",
            "frame-fpo",
            "no-structured-exception-handling",
            "no-clean-or-effective-ebp-derivation-from-esp",
        ],
    }


def _prove_pair(
    pair: CompilerStateCodePair,
    exception_mode: Mapping[str, object] | None,
    compiler_identity: Msvc420CompilerIdentity | None = None,
) -> dict[str, object]:
    _require_relocation_semantics(pair)
    clean_offsets, _clean_records = _relocation_parts(
        pair.clean_relocations, f"MSVC 4.20 compiler-state clean code {pair.owner!r}"
    )
    effective_offsets, effective_records = _relocation_parts(
        pair.effective_relocations, f"MSVC 4.20 compiler-state effective code {pair.owner!r}"
    )
    clean_instructions = _instructions(
        pair.clean_body,
        _clean_records,
        f"MSVC 4.20 compiler-state clean entry census {pair.owner!r}",
    )
    effective_instructions = _instructions(
        pair.effective_body,
        effective_records,
        f"MSVC 4.20 compiler-state effective entry census {pair.owner!r}",
    )
    clean_instruction_starts = {item["offset"] for item in clean_instructions}
    effective_instruction_starts = {item["offset"] for item in effective_instructions}
    invalid_entries = sorted(
        set(pair.external_entries) - (clean_instruction_starts & effective_instruction_starts)
    )
    if invalid_entries:
        raise ClassicSemanticError(
            f"MSVC 4.20 compiler-state code pair {pair.owner!r} has a non-instruction "
            f"external entry: {invalid_entries[:1]}"
        )
    frame_pointer_free_proof = _paired_frame_pointer_free_proof(
        pair,
        clean_instructions,
        effective_instructions,
    )
    state = _ImageState(pair.clean_body, list(clean_offsets))
    steps: list[dict[str, object]] = []
    saved_prologue = _try_saved_prologue_web_permutation(
        state,
        pair,
        clean_instructions,
        effective_instructions,
        _clean_records,
        effective_records,
        compiler_identity,
    )
    if saved_prologue is not None:
        state, proof = saved_prologue
        steps.append(proof)
    else:
        state, schedules = _apply_schedules(
            state,
            pair,
            pair.clean_relocations,
            effective_offsets,
            effective_records,
            pair.effective_relocations,
            structural=False,
            exception_mode=exception_mode,
            compiler_identity=compiler_identity,
        )
        steps.extend(schedules)
    if state.body != pair.effective_body:
        current_records = {
            offset: _clean_records[original]
            for offset, original in zip(state.relocation_offsets, clean_offsets, strict=True)
        }
        atomic = _try_atomic_schedule_web_with_source_algebraic(
            state,
            pair,
            current_records,
            effective_records,
            compiler_identity,
        )
        if atomic is not None:
            state, atomic_steps = atomic
            steps.extend(atomic_steps)
    if state.body != pair.effective_body:
        bijection = _try_register_bijection(
            state,
            pair,
            pair.clean_relocations,
            effective_offsets,
            effective_records,
            pair.effective_relocations,
        )
        if bijection is not None:
            state, proof = bijection
            steps.append(proof)
            state, schedules = _apply_schedules(
                state,
                pair,
                pair.clean_relocations,
                effective_offsets,
                effective_records,
                pair.effective_relocations,
                structural=False,
                exception_mode=exception_mode,
                compiler_identity=compiler_identity,
            )
            steps.extend(schedules)
    if state.body != pair.effective_body:
        state, schedules = _apply_schedules(
            state,
            pair,
            pair.clean_relocations,
            effective_offsets,
            effective_records,
            pair.effective_relocations,
            structural=True,
            exception_mode=exception_mode,
            compiler_identity=compiler_identity,
        )
        steps.extend(schedules)
        source_base_offsets, source_base_records = _relocation_parts(
            pair.clean_relocations, "MSVC 4.20 compiler-state source code"
        )
        current_records = {
            offset: source_base_records[original]
            for offset, original in zip(state.relocation_offsets, source_base_offsets, strict=True)
        }
        state, algebraic = _try_algebraic_residual(state, pair, current_records)
        steps.extend(algebraic)
        if state.body != pair.effective_body:
            try:
                state, proof = _prove_register_web_recolour(
                    state,
                    pair,
                    current_records,
                    effective_records,
                    frame_pointer_free=frame_pointer_free_proof is not None,
                )
                steps.append(proof)
            except ClassicSemanticError as web_error:
                bridged = _try_web_with_algebraic_residual(
                    state,
                    pair,
                    current_records,
                    effective_records,
                    frame_pointer_free=frame_pointer_free_proof is not None,
                )
                if bridged is None:
                    raise web_error
                state, bridge_steps = bridged
                steps.extend(bridge_steps)
    if state.body != pair.effective_body:
        raise ClassicSemanticError(
            f"MSVC 4.20 compiler-state code pair {pair.owner!r} fails exact image rejoin"
        )
    if state.relocation_offsets != effective_offsets:
        raise ClassicSemanticError(
            f"MSVC 4.20 compiler-state code pair {pair.owner!r} fails exact relocation rejoin"
        )
    moved_relocations = [
        {
            "ordinal": ordinal,
            "clean_offset": clean_offset,
            "effective_offset": effective_offset,
            "statement_digest": Digest.from_bytes(
                canonical_json(
                    {
                        key: value
                        for key, value in pair.clean_relocations[ordinal].items()
                        if key != "offset"
                    }
                )
            ).value,
        }
        for ordinal, (clean_offset, effective_offset) in enumerate(
            zip(clean_offsets, effective_offsets, strict=True)
        )
        if clean_offset != effective_offset
    ]
    result: dict[str, object] = {
        "owner": pair.owner,
        "clean_section_number": pair.clean_section_number,
        "effective_section_number": pair.effective_section_number,
        "topology_digest": pair.topology_digest,
        "clean_body_digest": Digest.from_bytes(pair.clean_body).value,
        "effective_body_digest": Digest.from_bytes(pair.effective_body).value,
        "body_size": len(pair.clean_body),
        "relocation_count": len(pair.clean_relocations),
        "moved_relocations": moved_relocations,
        "steps": steps,
        "closure": [
            "complete-target-code-image",
            "complete-instruction-control-flow",
            "register-value-reaching-definitions",
            "relocation-count-order-type-target-addend-and-instruction-field",
            "exact-relocation-seat-rejoin",
        ],
    }
    if frame_pointer_free_proof is not None:
        result["frame_pointer_free_evidence"] = frame_pointer_free_proof
    return result


def _compiler_invocation_statement(
    evidence: CompilerStateCompilerEvidence,
) -> Mapping[str, object]:
    return MappingProxyType(
        {
            "tool_id": evidence.tool_id,
            "tool_digest": evidence.tool_digest,
            "invocation_digest": evidence.invocation_digest,
            "arguments_digest": Digest.from_bytes(canonical_json(list(evidence.arguments))).value,
        }
    )


def _optional_synchronous_exception_mode(
    evidence: CompilerStateCompilerEvidence,
) -> Mapping[str, object] | None:
    folded = [argument.casefold() for argument in evidence.arguments]
    gx_ordinals = [ordinal for ordinal, argument in enumerate(folded) if argument in {"/gx", "-gx"}]
    conflicting = [
        argument
        for argument in evidence.arguments
        if argument.casefold().startswith(("/gx", "-gx", "/eh", "-eh"))
        and argument.casefold() not in {"/gx", "-gx"}
    ]
    if len(gx_ordinals) != 1 or conflicting:
        return None
    return MappingProxyType(
        {
            "model": _SYNCHRONOUS_EXCEPTION_MODEL,
            "argument": evidence.arguments[gx_ordinals[0]],
            "argument_ordinal": gx_ordinals[0],
            "arguments_digest": Digest.from_bytes(canonical_json(list(evidence.arguments))).value,
        }
    )


def derive_msvc420_compiler_state_projection(
    pairs: Sequence[CompilerStateCodePair],
    *,
    compiler_identity: Msvc420CompilerIdentity,
    compiler_evidence: CompilerStateCompilerEvidence,
) -> CompilerStateProjection | None:
    """Prove every retained code delta selected by an independent source gate."""

    if type(compiler_identity) is not Msvc420CompilerIdentity:
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state projection lacks a validated compiler identity"
        )
    compiler_tools = tuple(tool for tool in compiler_identity.tools if "compiler" in tool.roles)
    if len(compiler_tools) != 1 or compiler_evidence.tool_digest != compiler_tools[0].digest.value:
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state invocation is not bound to the validated compiler"
        )

    changed = sorted(
        (pair for pair in pairs if pair.clean_body != pair.effective_body),
        key=lambda pair: (
            pair.owner.casefold(),
            pair.owner,
            pair.clean_section_number,
            pair.effective_section_number,
        ),
    )
    if not changed:
        return None
    if len({pair.owner for pair in changed}) != len(changed):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state code projection has no unique external-owner pairing"
        )
    if len({pair.clean_section_number for pair in changed}) != len(changed):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state code projection reuses a clean section seat"
        )
    if len({pair.effective_section_number for pair in changed}) != len(changed):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state code projection reuses an effective section seat"
        )
    compiler_invocation = _compiler_invocation_statement(compiler_evidence)
    compiler_identity_receipt = compiler_identity.proof_receipt()
    compiler_identity_digest = compiler_identity.receipt_digest().value
    exception_mode = _optional_synchronous_exception_mode(compiler_evidence)
    section_proofs: list[dict[str, object]] = []
    for pair in changed:
        try:
            section_proofs.append(_prove_pair(pair, exception_mode, compiler_identity))
        except ClassicSemanticError as error:
            if pair.owner in str(error):
                raise
            raise ClassicSemanticError(
                f"MSVC 4.20 compiler-state code pair {pair.owner!r}: {error}"
            ) from error
    clean_certificates: dict[int, CompilerStateCodeCertificate] = {}
    effective_certificates: dict[int, CompilerStateCodeCertificate] = {}
    for pair, proof in zip(changed, section_proofs, strict=True):
        digest = Digest.from_bytes(
            canonical_json(
                {
                    "theorem": _THEOREM,
                    "compiler_identity_receipt_digest": compiler_identity_digest,
                    **proof,
                }
            )
        ).value
        certificate = CompilerStateCodeCertificate(_THEOREM, digest)
        clean_certificates[pair.clean_section_number] = certificate
        effective_certificates[pair.effective_section_number] = certificate
    proof = {
        "theorem": _THEOREM,
        "compiler_identity": compiler_identity_receipt,
        "compiler_invocation": dict(compiler_invocation),
        "exception_mode": dict(exception_mode) if exception_mode is not None else None,
        "sections": section_proofs,
        "preserved": [
            "all-unpaired-code-sections",
            "all-non-code-envelope-components",
            "ordinary-linkage-after-only-typed-row-subtraction",
            "complete-paired-section-topology",
            "terminal-locked-linker-and-literal-byte-closure",
        ],
    }
    return CompilerStateProjection(
        MappingProxyType(clean_certificates),
        MappingProxyType(effective_certificates),
        MappingProxyType(proof),
    )


__all__ = ["derive_msvc420_compiler_state_projection"]
