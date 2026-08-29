"""Atomic saved-prologue permutation plus register-web proof."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from reprobit.binary import ByteIdentityError
from reprobit.classic.compiler_identity import (
    MSVC420_WIN32_I386_TARGET,
    Msvc420CompilerIdentity,
)
from reprobit.classic.registers import require_no_ebp_frame_derivation
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest

from .compiler_state_foundation import (
    CompilerStateCodePair,
    _ImageState,
    _Instruction,
    _RelocationRecord,
)
from .compiler_state_prologue_evidence import (
    _debug_pair,
    _epilogues,
    _fpo_pair,
    _prologue_shape,
)
from .compiler_state_prologue_web import _prove_whole_function_web
from .compiler_state_prologue_window import (
    _prove_window_stack_and_dag,
    _try_saved_prologue_candidate,
)
from .stack_frontier_foundation import MAX_INSTRUCTIONS

_THEOREM = "msvc-4.20-saved-prologue-web-permutation-v1"


def _require(condition: object, message: str) -> None:
    if not condition:
        raise ClassicSemanticError(message)


def _try_saved_prologue_web_permutation(
    state: _ImageState,
    pair: CompilerStateCodePair,
    clean_instructions: Sequence[_Instruction],
    effective_instructions: Sequence[_Instruction],
    clean_records: Mapping[int, _RelocationRecord],
    effective_records: Mapping[int, _RelocationRecord],
    compiler_identity: Msvc420CompilerIdentity | None,
) -> tuple[_ImageState, dict[str, object]] | None:
    """Prove one indivisible prologue schedule and local register-web cycle."""

    evidence = pair.fpo_evidence
    if not (
        state.body == pair.clean_body
        and type(compiler_identity) is Msvc420CompilerIdentity
        and compiler_identity.target == MSVC420_WIN32_I386_TARGET
        and pair.eh_control_digest is None
        and not pair.external_entries
        and evidence is not None
        and pair.debug_evidence is not None
        and len(pair.clean_body) == len(pair.effective_body)
        and len(clean_instructions) == len(effective_instructions)
        and 1 <= len(clean_instructions) <= MAX_INSTRUCTIONS
        and clean_records == effective_records
        and sorted(clean_records) == state.relocation_offsets
    ):
        return None
    if not (
        len(evidence.clean_body) == len(evidence.effective_body) == 16
        and evidence.clean_body[14] != evidence.effective_body[14]
    ):
        return None

    selected = _try_saved_prologue_candidate(
        pair.clean_body,
        pair.effective_body,
        clean_instructions,
        effective_instructions,
        evidence.clean_body[14],
        evidence.effective_body[14],
    )
    if selected is None:
        return None

    # The structural theorem is selected; every check below is authoritative.
    clean_fpo, effective_fpo = _fpo_pair(pair)
    clean_shape = _prologue_shape(
        pair.clean_body,
        clean_instructions,
        clean_fpo,
        "MSVC 4.20 saved-prologue clean FPO boundary",
    )
    effective_shape = _prologue_shape(
        pair.effective_body,
        effective_instructions,
        effective_fpo,
        "MSVC 4.20 saved-prologue effective FPO boundary",
    )
    clean_saves = clean_shape["saves"]
    effective_saves = effective_shape["saves"]
    _require(
        clean_saves
        and [name for name, _index, _offset in clean_saves]
        == [name for name, _index, _offset in effective_saves]
        and clean_shape["locals_bytes"] == effective_shape["locals_bytes"]
        and clean_shape["floor"] == effective_shape["floor"],
        "MSVC 4.20 saved-prologue physical frame changes",
    )
    window_start = selected["start"]
    window_end = selected["end"]
    clean_window_indexes = selected["clean_indexes"]
    effective_window_indexes = selected["effective_indexes"]
    clean_window = selected["clean_window"]
    effective_window = selected["effective_window"]
    cycle = selected["cycle"]
    order = selected["order"]
    pair_index = selected["pair_index"]
    _require(
        window_start == clean_saves[0][2] == effective_saves[0][2]
        and pair.clean_body[:window_start] == pair.effective_body[:window_start],
        "MSVC 4.20 saved-prologue prefix or first save changes",
    )
    clean_boundaries = {int(item["offset"]) for item in clean_instructions}
    effective_boundaries = {int(item["offset"]) for item in effective_instructions}
    common_after = sorted(
        boundary
        for boundary in clean_boundaries & effective_boundaries
        if boundary > max(clean_shape["prolog_end"], effective_shape["prolog_end"])
    )
    _require(
        bool(common_after)
        and common_after[0] == window_end
        and clean_window_indexes
        == [
            index
            for index, item in enumerate(clean_instructions)
            if window_start <= int(item["offset"]) < window_end
        ]
        and effective_window_indexes
        == [
            index
            for index, item in enumerate(effective_instructions)
            if window_start <= int(item["offset"]) < window_end
        ],
        "MSVC 4.20 saved-prologue selected window differs from FPO boundaries",
    )
    _require(
        not any(
            window_start <= offset < window_end for offset in [*clean_records, *effective_records]
        )
        and all(
            not any(
                item.get("target") is not None
                and window_start < cast(int, item["target"]) < window_end
                for item in instructions
            )
            for instructions in (clean_instructions, effective_instructions)
        ),
        "MSVC 4.20 saved-prologue window contains a relocation or interior entry",
    )
    _require(
        set(cycle) <= {name for name, _index, _offset in clean_saves},
        "MSVC 4.20 saved-prologue web cycle contains an unsaved register",
    )

    try:
        require_no_ebp_frame_derivation(
            pair.clean_body,
            clean_instructions,
            "MSVC 4.20 saved-prologue clean code",
        )
        require_no_ebp_frame_derivation(
            pair.effective_body,
            effective_instructions,
            "MSVC 4.20 saved-prologue effective code",
        )
    except ByteIdentityError as error:
        raise ClassicSemanticError(str(error)) from error

    clean_to_effective_local = {source: target for target, source in enumerate(order)}
    clean_previous = next(
        index
        for index, item in enumerate(clean_instructions)
        if int(item["offset"]) + int(item["length"]) == clean_shape["prolog_end"]
    )
    effective_previous = pair_index[clean_previous]
    _require(
        int(effective_instructions[effective_previous]["offset"])
        + int(effective_instructions[effective_previous]["length"])
        == effective_shape["prolog_end"],
        "MSVC 4.20 saved-prologue boundary is not carried by instruction correspondence",
    )
    debug = _debug_pair(
        pair,
        clean_shape["prolog_end"],
        effective_shape["prolog_end"],
        clean_boundaries,
        effective_boundaries,
    )

    adjustments, save_by_register, target_position, window_proof = _prove_window_stack_and_dag(
        pair.clean_body,
        pair.effective_body,
        clean_window,
        effective_window,
        clean_to_effective_local,
        clean_window_indexes,
        clean_saves,
        order,
        cycle,
    )

    image, web_proof = _prove_whole_function_web(
        pair,
        clean_instructions,
        effective_instructions,
        clean_records,
        effective_records,
        clean_window_indexes,
        effective_window_indexes,
        pair_index,
        cycle,
        adjustments,
        save_by_register,
        target_position,
    )

    saved_names = [name for name, _index, _offset in clean_saves]
    parameter_bytes = cast(int, clean_fpo["cdwParams"]) * 4
    clean_epilogues = _epilogues(
        pair.clean_body,
        clean_instructions,
        saved_names,
        clean_shape["locals_bytes"],
        parameter_bytes,
        "MSVC 4.20 saved-prologue clean code",
    )
    effective_epilogues = _epilogues(
        pair.effective_body,
        effective_instructions,
        saved_names,
        effective_shape["locals_bytes"],
        parameter_bytes,
        "MSVC 4.20 saved-prologue effective code",
    )
    _require(
        clean_epilogues == effective_epilogues,
        "MSVC 4.20 saved-prologue physical restore closure changes",
    )

    return _ImageState(pair.effective_body, list(state.relocation_offsets)), {
        "kind": _THEOREM,
        "compiler_identity": compiler_identity.proof_receipt(),
        "window": {
            "start": window_start,
            "end": window_end,
            "target_order": order,
            "cycle": dict(sorted(cycle.items())),
            "stack_adjustments": adjustments,
            **window_proof,
        },
        "paired_metadata": {
            "fpo_receipt_digest": evidence.receipt_digest,
            "clean_fpo": clean_fpo,
            "effective_fpo": effective_fpo,
            "codeview": debug,
            "ordinary_line_table": "not-proof-authority; effective compiler product retained",
        },
        **web_proof,
        "epilogues": clean_epilogues,
        "exact_image_digest": Digest.from_bytes(bytes(image)).value,
        "relocation_offsets": list(state.relocation_offsets),
    }


__all__ = []
