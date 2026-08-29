"""Schema-v3 adapter for the finite classic simulated-elision quarantine.

This module is imported only by the explicit legacy execution path. It bridges
a frozen legacy intervention, its committed proof receipt, fresh compiler
objects, and a VA-only sealed-oracle capability.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType
from typing import Any

from reprobit.binary import ByteIdentityError
from reprobit.classic.legacy_elision import (
    SIMULATED_ELISION_CLASS,
    SIMULATED_ELISION_KIND,
    compose_retail_exact_simulated_elision,
)
from reprobit.legacy import LegacyInstallError, PE32VirtualAddressReader
from reprobit.model import ByteRange, Digest
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeFamily,
    LegacyOracleInstallIntervention,
    legacy_allowlist_digest,
)
from reprobit.strict_json import canonical_json

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HEX_ADDRESS = re.compile(r"^0[xX][0-9a-fA-F]{1,8}$")


@dataclass(frozen=True, slots=True)
class LegacySimulatedElisionResult:
    """A permanently quarantined object composition and runtime evidence."""

    output: bytes
    proof: Mapping[str, object]
    evidence_detail: Mapping[str, object]
    evidence_digest: Digest
    body_relative_ranges: tuple[ByteRange, ...]
    oracle_payload_bytes_read: int
    legacy_oracle_install: bool = True

    @property
    def clean(self) -> bool:
        return False

    @property
    def byte_count(self) -> int:
        return sum(item.length for item in self.body_relative_ranges)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise LegacyInstallError(message)


def _mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise LegacyInstallError(f"{context} must be an object")
    return value


def _positive_int(value: object, context: str) -> int:
    if type(value) is not int or value < 1:
        raise LegacyInstallError(f"{context} must be a positive integer")
    return value


def _digest(value: object, context: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise LegacyInstallError(f"{context} must be lowercase SHA-256")
    return value


def _address(value: object, context: str) -> int:
    if not isinstance(value, str) or not _HEX_ADDRESS.fullmatch(value):
        raise LegacyInstallError(f"{context} must be a 32-bit hexadecimal address")
    return int(value, 16)


def _validate_range_bindings(
    intervention: LegacyOracleInstallIntervention,
    simulated: Mapping[str, object],
    main_length: int,
) -> tuple[ByteRange, ...]:
    raw_regions = simulated.get("regions")
    if not isinstance(raw_regions, list) or len(raw_regions) != len(intervention.ranges):
        raise LegacyInstallError("legacy receipt region count differs from its intervention")
    body_ranges: list[ByteRange] = []
    previous_preimage_end = 0
    previous_output_end = 0
    for index, (declared, raw_region) in enumerate(
        zip(intervention.ranges, raw_regions, strict=True)
    ):
        region = _mapping(raw_region, f"legacy receipt region {index}")
        expected_values = (
            declared.preimage_range.offset,
            declared.preimage_range.end,
            declared.output_range.offset,
            declared.output_range.length,
        )
        received_values = tuple(
            region.get(key)
            for key in ("region_start", "region_end", "image_start", "image_length")
        )
        _require(
            received_values == expected_values,
            f"legacy receipt region {index} differs from its frozen range binding",
        )
        _require(
            declared.oracle_range == declared.output_range,
            f"legacy intervention region {index} does not bind oracle and output offsets",
        )
        _require(
            declared.oracle_range.end <= main_length,
            f"legacy intervention region {index} leaves the declared oracle body",
        )
        _require(
            declared.preimage_range.offset >= previous_preimage_end
            and declared.output_range.offset >= previous_output_end,
            "legacy intervention ranges are not in canonical non-overlapping order",
        )
        previous_preimage_end = declared.preimage_range.end
        previous_output_end = declared.output_range.end
        body_ranges.append(declared.output_range)
    _require(
        sum(item.length for item in body_ranges) == intervention.byte_count,
        "legacy intervention byte count differs from its frozen ranges",
    )
    return tuple(body_ranges)


def _fetch_auxiliary_oracles(
    simulated: Mapping[str, object],
    oracle: PE32VirtualAddressReader,
) -> tuple[dict[str, bytes], list[dict[str, object]], int]:
    bodies: dict[str, bytes] = {}
    evidence: list[dict[str, object]] = []
    payload_bytes = 0
    for key, kind in (("callee_oracles", "callee"), ("vtable_oracles", "vtable")):
        raw_items = simulated.get(key, [])
        if not isinstance(raw_items, list):
            raise LegacyInstallError(f"legacy {kind} oracle declarations must be an array")
        for index, raw_item in enumerate(raw_items):
            item = _mapping(raw_item, f"legacy {kind} oracle {index}")
            symbol = item.get("symbol")
            if not isinstance(symbol, str) or not symbol:
                raise LegacyInstallError(f"legacy {kind} oracle {index} has no symbol")
            if symbol in bodies:
                raise LegacyInstallError(f"legacy auxiliary oracle repeats symbol {symbol!r}")
            address = _address(item.get("address"), f"legacy {kind} oracle {symbol!r} address")
            length = _positive_int(
                item.get("length"), f"legacy {kind} oracle {symbol!r} length"
            )
            pinned_digest = _digest(
                item.get("body_sha256"), f"legacy {kind} oracle {symbol!r} digest"
            )
            body = oracle.read_virtual_address(address, length)
            received_digest = sha256(body).hexdigest()
            _require(
                received_digest == pinned_digest,
                f"legacy {kind} oracle {symbol!r} differs from its committed digest",
            )
            bodies[symbol] = body
            payload_bytes += length
            evidence.append(
                {
                    "kind": kind,
                    "symbol": symbol,
                    "address": address,
                    "length": length,
                    "body_sha256": received_digest,
                }
            )
    return bodies, evidence, payload_bytes


def compose_legacy_simulated_elision(
    intervention: LegacyOracleInstallIntervention,
    receipt: ClassicProofReceipt,
    seed_object: bytes,
    donor_object: bytes,
    oracle: PE32VirtualAddressReader,
) -> LegacySimulatedElisionResult:
    """Execute one exactly frozen simulated-elision legacy intervention.

    The caller supplies fresh seed/donor objects and only a PE virtual-address
    reader.  All oracle reads are derived from the committed receipt; no path,
    file offset, arbitrary range, or caller-provided payload crosses this API.
    """

    _require(
        isinstance(intervention, LegacyOracleInstallIntervention),
        "legacy composition requires a legacy oracle-install intervention",
    )
    _require(
        isinstance(receipt, ClassicProofReceipt),
        "legacy composition requires a classic proof receipt",
    )
    _require(isinstance(oracle, PE32VirtualAddressReader), "legacy oracle is not VA-bound")
    _require(type(seed_object) is bytes and bool(seed_object), "legacy seed object is empty")
    _require(type(donor_object) is bytes and bool(donor_object), "legacy donor object is empty")
    _require(
        receipt.intervention_id == intervention.id,
        "legacy proof receipt names a different intervention",
    )
    _require(
        receipt.family is ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION,
        "legacy proof receipt has the wrong classic family",
    )
    _require(not receipt.redactions, "legacy proof receipt contains unavailable redactions")
    _require(
        intervention.scope.function is not None
        and intervention.scope.translation_unit is not None,
        "legacy intervention must have translation-unit and function scope",
    )
    _require(
        intervention.oracle_target == intervention.scope.target,
        "legacy oracle target differs from the intervention scope",
    )
    _require(
        len(intervention.dependencies) == 1,
        "legacy simulated elision requires exactly one donor dependency",
    )
    expected_allowlist = legacy_allowlist_digest(intervention)
    _require(
        expected_allowlist == intervention.allowlist_digest,
        "legacy intervention differs from its frozen allowlist material",
    )
    _require(
        Digest.from_bytes(canonical_json(receipt)) == intervention.proof_receipt_digest,
        "legacy proof receipt differs from its frozen digest",
    )

    expected_values = deepcopy(receipt.expected_values)
    simulated = _mapping(
        expected_values.get("simulated_elision"), "legacy simulated-elision declaration"
    )
    _require(
        simulated.get("kind") == SIMULATED_ELISION_KIND,
        "legacy simulated-elision declaration has the wrong schema",
    )
    preimage_key = (
        "expected_donor_body_sha256"
        if simulated.get("pre_image") == "donor"
        else "expected_seed_body_sha256"
    )
    _require(
        _digest(expected_values.get(preimage_key), "legacy preimage binding")
        == intervention.preimage_digest.value,
        "legacy receipt preimage digest differs from its intervention",
    )
    _require(
        _digest(expected_values.get("expected_body_sha256"), "legacy output-body binding")
        == intervention.oracle_body_digest.value,
        "legacy receipt output-body digest differs from its intervention",
    )
    retail_oracle = _mapping(
        expected_values.get("retail_oracle"), "legacy main oracle declaration"
    )
    main_address = _address(retail_oracle.get("address"), "legacy main oracle address")
    main_length = _positive_int(retail_oracle.get("length"), "legacy main oracle length")
    _require(
        main_address == intervention.oracle_address,
        "legacy receipt oracle address differs from its intervention",
    )
    body_ranges = _validate_range_bindings(intervention, simulated, main_length)

    main_body = oracle.read_virtual_address(main_address, main_length)
    auxiliary_bodies, auxiliary_evidence, auxiliary_bytes = _fetch_auxiliary_oracles(
        simulated, oracle
    )
    function: dict[str, Any] = dict(expected_values)
    function["mangled"] = intervention.scope.function
    function["splice_class"] = SIMULATED_ELISION_CLASS
    try:
        output, raw_proof = compose_retail_exact_simulated_elision(
            seed_object,
            donor_object,
            function,
            main_body,
            auxiliary_bodies,
        )
    except (ByteIdentityError, KeyError, TypeError, ValueError) as error:
        raise LegacyInstallError(f"legacy simulated-elision proof failed: {error}") from error
    _require(type(output) is bytes and bool(output), "legacy composer returned an empty object")
    _require(isinstance(raw_proof, Mapping), "legacy composer returned malformed proof evidence")
    proof: dict[str, object] = dict(raw_proof)
    _require(proof.get("retail_exact") is True, "legacy composer did not prove exactness")
    try:
        proof_digest = Digest.from_bytes(canonical_json(proof))
    except (TypeError, ValueError) as error:
        raise LegacyInstallError(
            f"legacy composer returned non-canonical evidence: {error}"
        ) from error

    main_runtime_digest = sha256(main_body).hexdigest()
    payload_bytes = main_length + auxiliary_bytes
    _require(
        payload_bytes == intervention.maximum_oracle_payload_bytes,
        "legacy oracle payload reads differ from the frozen ceiling",
    )
    evidence: dict[str, object] = {
        "schema": "legacy-simulated-elision-evidence-v1",
        "intervention_id": intervention.id,
        "receipt_id": receipt.id,
        "target_id": intervention.scope.target,
        "translation_unit_id": intervention.scope.translation_unit,
        "function": intervention.scope.function,
        "dependency_id": intervention.dependencies[0],
        "allowlist_digest": intervention.allowlist_digest.value,
        "proof_receipt_digest": intervention.proof_receipt_digest.value,
        "preimage_digest": intervention.preimage_digest.value,
        "oracle_body_digest": intervention.oracle_body_digest.value,
        "oracle_target": intervention.oracle_target,
        "oracle_address": intervention.oracle_address,
        "main_oracle_length": main_length,
        "main_oracle_runtime_sha256": main_runtime_digest,
        "auxiliary_oracles": auxiliary_evidence,
        "body_relative_ranges": [item.model_dump(mode="json") for item in body_ranges],
        "installed_byte_count": intervention.byte_count,
        "oracle_payload_bytes_read": payload_bytes,
        "maximum_oracle_payload_bytes": intervention.maximum_oracle_payload_bytes,
        "seed_object": {
            "digest": Digest.from_bytes(seed_object).model_dump(mode="json"),
            "size": len(seed_object),
        },
        "donor_object": {
            "digest": Digest.from_bytes(donor_object).model_dump(mode="json"),
            "size": len(donor_object),
        },
        "output_sha256": sha256(output).hexdigest(),
        "output_size": len(output),
        "candidate": {
            "digest": Digest.from_bytes(output).model_dump(mode="json"),
            "size": len(output),
        },
        "proof_digest": proof_digest.value,
        "legacy_oracle_install": True,
        "clean": False,
    }
    evidence_digest = Digest.from_bytes(canonical_json(evidence))
    return LegacySimulatedElisionResult(
        output=output,
        proof=MappingProxyType(proof),
        evidence_detail=MappingProxyType(evidence),
        evidence_digest=evidence_digest,
        body_relative_ranges=body_ranges,
        oracle_payload_bytes_read=payload_bytes,
    )


__all__ = [
    "LegacySimulatedElisionResult",
    "compose_legacy_simulated_elision",
]
