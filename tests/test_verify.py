from __future__ import annotations

import os
from pathlib import Path

import pytest

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


def test_sealed_oracle_cannot_be_overridden_by_a_forged_comparator() -> None:
    with pytest.raises(TypeError, match="cannot be subclassed"):

        class ForgedOracle(SealedFileOracle):
            pass
