from __future__ import annotations

import os
from pathlib import Path

import pytest

import reprobit.verify as verify_module
from reprobit.verify import (
    LiteralVerifier,
    SealedFileOracle,
    VerificationError,
    seal_file_oracle,
)


def test_literal_verifier_reports_equality_without_exposing_payload(tmp_path: Path) -> None:
    reference = tmp_path / "reference.bin"
    candidate = tmp_path / "candidate.bin"
    reference.write_bytes(b"abcdef")
    candidate.write_bytes(b"abcdef")

    with seal_file_oracle(reference) as oracle:
        assert not hasattr(oracle, "path")
        assert not hasattr(oracle, "read")
        receipt = LiteralVerifier(chunk_size=2).verify(candidate, oracle)

    assert receipt.byte_exact
    assert receipt.first_difference_offset is None
    assert receipt.candidate_digest == receipt.oracle_digest
    assert receipt.candidate_size == receipt.oracle_size == 6


def test_literal_verifier_reports_first_difference_and_size(tmp_path: Path) -> None:
    reference = tmp_path / "reference.bin"
    candidate = tmp_path / "candidate.bin"
    reference.write_bytes(b"abcdef")
    candidate.write_bytes(b"abcxef-more")

    with seal_file_oracle(reference) as oracle:
        receipt = LiteralVerifier(chunk_size=3).verify(candidate, oracle)

    assert not receipt.byte_exact
    assert receipt.first_difference_offset == 3
    assert receipt.candidate_size == 11
    assert receipt.oracle_size == 6


def test_closed_oracle_capability_cannot_be_reused(tmp_path: Path) -> None:
    reference = tmp_path / "reference.bin"
    candidate = tmp_path / "candidate.bin"
    reference.write_bytes(b"x")
    candidate.write_bytes(b"x")
    oracle = seal_file_oracle(reference)
    oracle.close()

    with pytest.raises(VerificationError, match="closed"):
        LiteralVerifier().verify(candidate, oracle)


def test_candidate_may_not_alias_the_sealed_oracle(tmp_path: Path) -> None:
    reference = tmp_path / "reference.bin"
    candidate = tmp_path / "candidate.bin"
    reference.write_bytes(b"oracle")
    os.link(reference, candidate)

    with (
        seal_file_oracle(reference) as oracle,
        pytest.raises(VerificationError, match="aliases"),
    ):
        LiteralVerifier().verify(candidate, oracle)


def test_sealed_oracle_may_not_change_after_it_is_opened(tmp_path: Path) -> None:
    reference = tmp_path / "reference.bin"
    candidate = tmp_path / "candidate.bin"
    reference.write_bytes(b"before")
    candidate.write_bytes(b"after!")

    with seal_file_oracle(reference) as oracle:
        reference.write_bytes(b"after!")
        with pytest.raises(VerificationError, match="changed before"):
            LiteralVerifier().verify(candidate, oracle)


def test_sealed_oracle_content_commitment_survives_metadata_collision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = tmp_path / "reference.bin"
    candidate = tmp_path / "candidate.bin"
    reference.write_bytes(b"before")
    candidate.write_bytes(b"after!")

    frozen_identity = (0, 0, 0, 0, 0, 0)
    monkeypatch.setattr(verify_module, "_stat_identity", lambda _: frozen_identity)
    with seal_file_oracle(reference) as oracle:
        reference.write_bytes(b"after!")
        with pytest.raises(VerificationError, match="changed before"):
            LiteralVerifier().verify(candidate, oracle)


def test_quarantined_read_authenticates_only_covered_blocks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = tmp_path / "reference.bin"
    reference.write_bytes(b"a" * (verify_module._INTEGRITY_BLOCK_SIZE + 1))

    frozen_identity = (0, 0, 0, 0, 0, 0)
    monkeypatch.setattr(verify_module, "_stat_identity", lambda _: frozen_identity)
    with seal_file_oracle(reference) as oracle:
        reads: list[tuple[int, int]] = []
        original_read = SealedFileOracle._read_at

        def observed_read(value: SealedFileOracle, offset: int, length: int) -> bytes:
            reads.append((offset, length))
            return original_read(value, offset, length)

        monkeypatch.setattr(SealedFileOracle, "_read_at", observed_read)
        reference.write_bytes(b"b" * (verify_module._INTEGRITY_BLOCK_SIZE + 1))
        with pytest.raises(VerificationError, match="changed before quarantined read"):
            oracle._read_exact_at(0, 1)
        assert reads == [(0, verify_module._INTEGRITY_BLOCK_SIZE)]


def test_sealed_oracle_cannot_be_overridden_by_a_forged_comparator() -> None:
    with pytest.raises(TypeError, match="cannot be subclassed"):

        class ForgedOracle(SealedFileOracle):
            pass
