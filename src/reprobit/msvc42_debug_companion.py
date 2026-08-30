"""One pure stabilizer for a noncertifying MSVC 4.2 image/PDB pair."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from reprobit.binary import require
from reprobit.classic.pe_metadata import (
    PE32MetadataTimes,
    apply_pe_metadata_candidate,
    read_pe32_metadata_times,
)
from reprobit.msvc42_pdb import (
    MSVC42_PDB_CANONICALIZATION_POLICY,
    PdbCanonicalizationAudit,
    canonicalize_msvc42_pdb,
    read_msvc42_pdb_identity,
)
from reprobit.msvc42_pe_debug import (
    MSVC42_DEBUG_COMPANION_POLICY,
    DebugCompanionCanonicalizationAudit,
    canonicalize_msvc42_debug_companion,
    read_msvc42_debug_companion_identity,
)

MSVC42_DEBUG_PAIR_POLICY = "msvc42-debug-pair-v1"


@dataclass(frozen=True, slots=True)
class DebugPairMetadataWrite:
    """One parsed export/resource/COFF timestamp normalization."""

    file_offset: int
    before: int
    after: int


@dataclass(frozen=True, slots=True)
class Msvc42DebugPairAudit:
    """Complete byte-level account for one stabilized companion pair."""

    policy_version: str
    certified_image_sha256: str
    times: PE32MetadataTimes
    image_debug: DebugCompanionCanonicalizationAudit
    image_bytes_outside_policy_ranges_sha256: str
    image_metadata_input_sha256: str
    image_metadata_output_sha256: str
    image_metadata_writes: tuple[DebugPairMetadataWrite, ...]
    pdb: PdbCanonicalizationAudit


@dataclass(frozen=True, slots=True)
class StabilizedMsvc42DebugCompanion:
    """Immutable matched analysis image/PDB bytes and their audit."""

    image: bytes
    pdb: bytes
    audit: Msvc42DebugPairAudit


def _metadata_writes(proof: dict[str, object]) -> tuple[DebugPairMetadataWrite, ...]:
    raw_writes = proof.get("writes")
    require(isinstance(raw_writes, list), "PE metadata audit lacks its write list")
    assert isinstance(raw_writes, list)
    writes: list[DebugPairMetadataWrite] = []
    for raw in raw_writes:
        require(isinstance(raw, dict), "PE metadata audit write is malformed")
        assert isinstance(raw, dict)
        offset = raw.get("file_offset")
        before = raw.get("before")
        after = raw.get("after")
        require(
            type(offset) is int and type(before) is int and type(after) is int,
            "PE metadata audit write is not integral",
        )
        assert isinstance(offset, int)
        assert isinstance(before, int)
        assert isinstance(after, int)
        writes.append(DebugPairMetadataWrite(offset, before, after))
    return tuple(writes)


def _outside_policy_ranges_sha256(
    raw: bytes,
    output: bytes,
    ranges: tuple[tuple[int, int], ...],
) -> str:
    """Hash the identical projection outside a closed set of eligible ranges."""

    require(len(raw) == len(output), "debug-companion normalization changed file size")
    preserved_raw = bytearray(raw)
    preserved_output = bytearray(output)
    for start, end in ranges:
        require(0 <= start < end <= len(raw), "debug-companion policy range exceeds the image")
        preserved_raw[start:end] = b"\0" * (end - start)
        preserved_output[start:end] = b"\0" * (end - start)
    require(
        preserved_raw == preserved_output,
        "debug-companion stabilization changed a byte outside its audited ranges",
    )
    return sha256(preserved_raw).hexdigest()


def stabilize_msvc42_debug_companion(
    certified_image: bytes,
    raw_image: bytes,
    raw_pdb: bytes,
    *,
    expected_pdb_path: str,
) -> StabilizedMsvc42DebugCompanion:
    """Stabilize only proven bookkeeping in a producer-matched VC 4.2 pair.

    The certified image supplies authentic link/resource clock values, but its
    layout and bytes are never mixed into the companion.  The raw NB10/PDB
    identity is checked before edits and the final identity is checked again.
    Symbols, types, addresses, paths, lines, FPO data, and section layout stay
    owned by the original ``/DEBUG`` relink.
    """

    require(type(certified_image) is bytes, "certified image must be immutable bytes")
    require(type(raw_image) is bytes, "raw debug-companion image must be immutable bytes")
    require(type(raw_pdb) is bytes, "raw debug-companion PDB must be immutable bytes")
    times = read_pe32_metadata_times(certified_image)
    raw_pdb_identity = read_msvc42_pdb_identity(raw_pdb)
    raw_image_identity = read_msvc42_debug_companion_identity(
        raw_image,
        expected_pdb_path=expected_pdb_path,
    )
    require(
        raw_image_identity.pdb_identity == raw_pdb_identity,
        "raw MSVC 4.2 debug image and PDB identities differ",
    )

    debug_image = canonicalize_msvc42_debug_companion(
        raw_image,
        link_time=times.link_time,
        expected_pdb_path=expected_pdb_path,
        expected_input_pdb_identity=raw_pdb_identity,
    )
    image, metadata_proof = apply_pe_metadata_candidate(
        debug_image.data,
        {
            "link_time": times.link_time,
            "resource_time": times.resource_time,
        },
    )
    pdb = canonicalize_msvc42_pdb(
        raw_pdb,
        link_time=times.link_time,
        expected_input_identity=raw_pdb_identity,
    )
    metadata_writes = _metadata_writes(metadata_proof)
    image_outside_policy_ranges_sha256 = _outside_policy_ranges_sha256(
        raw_image,
        image,
        tuple((write.file_offset, write.file_offset + 4) for write in debug_image.audit.writes)
        + tuple((write.file_offset, write.file_offset + 4) for write in metadata_writes),
    )

    final_image_identity = read_msvc42_debug_companion_identity(
        image,
        expected_pdb_path=expected_pdb_path,
    )
    final_pdb_identity = read_msvc42_pdb_identity(pdb.data)
    require(
        final_image_identity.pdb_identity == final_pdb_identity,
        "stabilized MSVC 4.2 debug image and PDB identities differ",
    )
    require(
        read_pe32_metadata_times(image) == times,
        "stabilized debug image differs from certified metadata authority",
    )
    require(
        metadata_proof.get("input_sha256") == debug_image.audit.output_sha256,
        "PE metadata audit is not chained to the debug-image audit",
    )
    output_sha256 = metadata_proof.get("output_sha256")
    require(
        type(output_sha256) is str and output_sha256 == sha256(image).hexdigest(),
        "PE metadata output audit differs from the stabilized image",
    )
    assert isinstance(output_sha256, str)
    require(
        pdb.audit.policy_version == MSVC42_PDB_CANONICALIZATION_POLICY
        and debug_image.audit.policy_version == MSVC42_DEBUG_COMPANION_POLICY,
        "debug-pair sub-policy version differs",
    )
    return StabilizedMsvc42DebugCompanion(
        image,
        pdb.data,
        Msvc42DebugPairAudit(
            policy_version=MSVC42_DEBUG_PAIR_POLICY,
            certified_image_sha256=sha256(certified_image).hexdigest(),
            times=times,
            image_debug=debug_image.audit,
            image_bytes_outside_policy_ranges_sha256=(image_outside_policy_ranges_sha256),
            image_metadata_input_sha256=debug_image.audit.output_sha256,
            image_metadata_output_sha256=output_sha256,
            image_metadata_writes=metadata_writes,
            pdb=pdb.audit,
        ),
    )


__all__ = [
    "MSVC42_DEBUG_PAIR_POLICY",
    "DebugPairMetadataWrite",
    "Msvc42DebugPairAudit",
    "StabilizedMsvc42DebugCompanion",
    "stabilize_msvc42_debug_companion",
]
