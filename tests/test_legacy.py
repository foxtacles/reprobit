from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from reprobit import classic_legacy
from reprobit.artifacts import digest_bytes
from reprobit.classic_legacy import compose_legacy_simulated_elision
from reprobit.legacy import (
    LegacyCopyRange,
    LegacyFileOracle,
    LegacyInstallError,
    LegacyOracleInstall,
    LegacyOracleInstallGate,
    LegacyPolicy,
    bind_pe32_oracle,
)
from reprobit.model import ByteRange, Digest, Scope
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeFamily,
    LegacyOracleInstallIntervention,
    OracleInstallRange,
)
from reprobit.strict_json import canonical_json
from reprobit.verify import seal_file_oracle


def _action(candidate: bytes, oracle: bytes) -> LegacyOracleInstall:
    return LegacyOracleInstall(
        "legacy.function",
        (
            LegacyCopyRange(
                output_offset=2,
                oracle_offset=1,
                length=3,
                preimage_digest=digest_bytes(candidate[2:5]),
                oracle_digest=digest_bytes(oracle[1:4]),
            ),
        ),
    )


def test_frozen_gate_installs_only_allowlisted_ranges_and_quarantines(tmp_path: Path) -> None:
    candidate = b"abcdefgh"
    oracle_bytes = b"0XYZ4567"
    reference = tmp_path / "reference.bin"
    reference.write_bytes(oracle_bytes)
    action = _action(candidate, oracle_bytes)
    gate = LegacyOracleInstallGate(LegacyPolicy.freeze((action,)))

    with LegacyFileOracle.open(reference) as oracle:
        output, receipt = gate.apply(candidate, oracle, (action,))

    assert output == b"abXYZfgh"
    assert receipt.byte_count == 3
    assert not receipt.toolchain_origin
    assert not receipt.clean
    quarantine = receipt.quarantine(artifact_id="output.image")
    assert quarantine.byte_count == 3
    assert quarantine.ranges[0].offset == 2


def test_changed_or_new_action_is_rejected_before_oracle_read(tmp_path: Path) -> None:
    candidate = b"abcdefgh"
    oracle_bytes = b"0XYZ4567"
    original = _action(candidate, oracle_bytes)
    changed = LegacyOracleInstall(
        original.id,
        (
            LegacyCopyRange(
                output_offset=1,
                oracle_offset=1,
                length=3,
                preimage_digest=digest_bytes(candidate[1:4]),
                oracle_digest=digest_bytes(oracle_bytes[1:4]),
            ),
        ),
    )
    reference = tmp_path / "reference.bin"
    reference.write_bytes(oracle_bytes)

    with (
        LegacyFileOracle.open(reference) as oracle,
        pytest.raises(LegacyInstallError, match="new or differs"),
    ):
        LegacyOracleInstallGate(LegacyPolicy.freeze((original,))).apply(
            candidate, oracle, (changed,)
        )


def test_preimage_drift_fails_closed(tmp_path: Path) -> None:
    candidate = b"abcdefgh"
    oracle_bytes = b"0XYZ4567"
    action = _action(candidate, oracle_bytes)
    reference = tmp_path / "reference.bin"
    reference.write_bytes(oracle_bytes)

    with (
        LegacyFileOracle.open(reference) as oracle,
        pytest.raises(LegacyInstallError, match="preimage"),
    ):
        LegacyOracleInstallGate(LegacyPolicy.freeze((action,))).apply(
            b"abQQQfgh", oracle, (action,)
        )


def test_disabled_policy_refuses_any_action(tmp_path: Path) -> None:
    candidate = b"abcdefgh"
    oracle_bytes = b"0XYZ4567"
    action = _action(candidate, oracle_bytes)
    reference = tmp_path / "reference.bin"
    reference.write_bytes(oracle_bytes)
    disabled = LegacyPolicy(False, (), 0, 0, 0)

    with (
        LegacyFileOracle.open(reference) as oracle,
        pytest.raises(LegacyInstallError, match="disabled"),
    ):
        LegacyOracleInstallGate(disabled).apply(candidate, oracle, (action,))


def _write_int(image: bytearray, offset: int, value: int, width: int) -> None:
    image[offset : offset + width] = value.to_bytes(width, "little")


def _pe32_image(payloads: dict[int, bytes]) -> bytes:
    image = bytearray(0x600)
    image[:2] = b"MZ"
    nt_offset = 0x80
    _write_int(image, 0x3C, nt_offset, 4)
    image[nt_offset : nt_offset + 4] = b"PE\0\0"
    _write_int(image, nt_offset + 4, 0x014C, 2)
    _write_int(image, nt_offset + 6, 1, 2)
    _write_int(image, nt_offset + 20, 0xE0, 2)
    optional = nt_offset + 24
    _write_int(image, optional, 0x010B, 2)
    _write_int(image, optional + 28, 0x00400000, 4)
    _write_int(image, optional + 32, 0x1000, 4)
    _write_int(image, optional + 36, 0x200, 4)
    _write_int(image, optional + 56, 0x2000, 4)
    _write_int(image, optional + 60, 0x200, 4)
    section = optional + 0xE0
    image[section : section + 8] = b".text\0\0\0"
    _write_int(image, section + 8, 0x500, 4)
    _write_int(image, section + 12, 0x1000, 4)
    _write_int(image, section + 16, 0x400, 4)
    _write_int(image, section + 20, 0x200, 4)
    for rva, payload in payloads.items():
        raw_offset = 0x200 + rva - 0x1000
        image[raw_offset : raw_offset + len(payload)] = payload
    return bytes(image)


def test_pe32_oracle_reader_exposes_only_strict_virtual_ranges(tmp_path: Path) -> None:
    reference = tmp_path / "reference.bin"
    reference.write_bytes(_pe32_image({0x1020: b"mapped"}))

    with seal_file_oracle(reference) as sealed:
        reader = bind_pe32_oracle(sealed)
        assert reader.image_base == 0x00400000
        assert reader.read_virtual_address(0x00401020, 6) == b"mapped"
        assert reader.read_virtual_address(0x00400000, 2) == b"MZ"
        with pytest.raises(LegacyInstallError, match="zero-fill"):
            reader.read_virtual_address(0x004013FF, 2)
        with pytest.raises(LegacyInstallError, match="one mapped section"):
            reader.read_virtual_address(0x00400FFF, 2)

    with pytest.raises(LegacyInstallError, match="sealed PE32 oracle"):
        reader.read_virtual_address(0x00401020, 1)


def _simulated_elision_fixture() -> tuple[
    LegacyOracleInstallIntervention,
    ClassicProofReceipt,
    dict[int, bytes],
]:
    main_address = 0x00401000
    callee_address = 0x00401020
    vtable_address = 0x00401040
    main_body = b"\x90\x91\x92\xc3"
    callee_body = b"\x01\x02\x03"
    vtable_body = callee_address.to_bytes(4, "little")
    preimage_digest = Digest.from_bytes(b"seed-body")
    output_body_digest = Digest.from_bytes(b"derived-body")
    ranges = (
        OracleInstallRange(
            preimage_range=ByteRange(offset=1, length=2),
            output_range=ByteRange(offset=1, length=2),
            oracle_range=ByteRange(offset=1, length=2),
        ),
    )
    simulated = {
        "kind": "simulated_elision_v1",
        "regions": [
            {
                "region_start": 1,
                "region_end": 3,
                "image_start": 1,
                "image_length": 2,
            }
        ],
        "callee_oracles": [
            {
                "symbol": "?callee@@YAXXZ",
                "address": hex(callee_address),
                "length": len(callee_body),
                "body_sha256": digest_bytes(callee_body),
            }
        ],
        "vtable_oracles": [
            {
                "symbol": "??_7fixture@@6B@",
                "address": hex(vtable_address),
                "length": len(vtable_body),
                "body_sha256": digest_bytes(vtable_body),
                "slots": {"0": "?callee@@YAXXZ"},
            }
        ],
    }
    receipt = ClassicProofReceipt(
        id="proof.fixture",
        intervention_id="legacy.action",
        family=ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION,
        expected_values={
            "expected_body_sha256": output_body_digest.value,
            "expected_seed_body_sha256": preimage_digest.value,
            "retail_oracle": {
                "address": hex(main_address),
                "length": len(main_body),
            },
            "simulated_elision": simulated,
        },
    )
    intervention = LegacyOracleInstallIntervention.freeze(
        id="legacy.action",
        scope=Scope(target="program", translation_unit="unit", function="?fixture@@YAXXZ"),
        rationale="Finite synthetic compatibility action.",
        dependencies=("donor.fixture",),
        proof_receipt_digest=Digest.from_bytes(canonical_json(receipt)),
        preimage_digest=preimage_digest,
        oracle_body_digest=output_body_digest,
        oracle_target="program",
        oracle_address=main_address,
        ranges=ranges,
        byte_count=2,
        maximum_oracle_payload_bytes=11,
    )
    return intervention, receipt, {
        0x1000: main_body,
        0x1020: callee_body,
        0x1040: vtable_body,
    }


def test_schema_v3_simulated_elision_fetches_only_declared_va_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    intervention, receipt, payloads = _simulated_elision_fixture()
    reference = tmp_path / "reference.bin"
    reference.write_bytes(_pe32_image(payloads))
    received: dict[str, object] = {}

    def compose(
        seed: bytes,
        donor: bytes,
        function: dict[str, Any],
        main_body: bytes,
        auxiliary: dict[str, bytes],
    ) -> tuple[bytes, dict[str, object]]:
        received.update(
            seed=seed,
            donor=donor,
            function=function,
            main_body=main_body,
            auxiliary=auxiliary,
        )
        return b"composed-object", {"retail_exact": True, "proof_kind": "synthetic"}

    monkeypatch.setattr(classic_legacy, "compose_retail_exact_simulated_elision", compose)
    with seal_file_oracle(reference) as sealed:
        result = compose_legacy_simulated_elision(
            intervention,
            receipt,
            b"fresh-seed-object",
            b"fresh-donor-object",
            bind_pe32_oracle(sealed),
        )

    assert result.output == b"composed-object"
    assert result.legacy_oracle_install
    assert not result.clean
    assert result.byte_count == 2
    assert result.oracle_payload_bytes_read == 11
    assert result.evidence_detail["candidate"] == {
        "digest": Digest.from_bytes(result.output).model_dump(mode="json"),
        "size": len(result.output),
    }
    assert result.evidence_detail["output_size"] == len(result.output)
    assert received["main_body"] == payloads[0x1000]
    assert received["auxiliary"] == {
        "?callee@@YAXXZ": payloads[0x1020],
        "??_7fixture@@6B@": payloads[0x1040],
    }
    function = received["function"]
    assert isinstance(function, dict)
    assert function["mangled"] == intervention.scope.function
    assert function["splice_class"] == "retail_exact_simulated_elision"
    assert result.evidence_detail["legacy_oracle_install"] is True


def test_simulated_elision_refuses_changed_allowlist_before_oracle_read(
    tmp_path: Path,
) -> None:
    intervention, receipt, payloads = _simulated_elision_fixture()
    changed = intervention.model_copy(update={"allowlist_digest": Digest.from_bytes(b"changed")})
    reference = tmp_path / "reference.bin"
    reference.write_bytes(_pe32_image(payloads))

    with (
        seal_file_oracle(reference) as sealed,
        pytest.raises(LegacyInstallError, match="frozen allowlist"),
    ):
        compose_legacy_simulated_elision(
            changed,
            receipt,
            b"fresh-seed-object",
            b"fresh-donor-object",
            bind_pe32_oracle(sealed),
        )
