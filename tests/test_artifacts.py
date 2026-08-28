from __future__ import annotations

from pathlib import Path

import pytest

from reprobit.artifacts import (
    AncestryNode,
    ArtifactRangeMap,
    ByteOrigin,
    ByteRange,
    ProvenanceError,
    ProvenanceGraph,
    RangeAncestry,
    digest_bytes,
    digest_file,
    validate_artifact_digest,
)


def test_byte_ranges_are_half_open() -> None:
    left = ByteRange(2, 6)
    right = ByteRange(6, 9)
    overlap = ByteRange(4, 8)

    assert left.length == 4
    assert not left.intersects(right)
    assert left.intersection(overlap) == ByteRange(4, 6)
    assert ByteRange(0, 10).contains(left)


@pytest.mark.parametrize("start,end", [(-1, 1), (0, 0), (3, 2)])
def test_byte_ranges_reject_empty_or_inverted_values(start: int, end: int) -> None:
    with pytest.raises(ProvenanceError):
        ByteRange(start, end)


def test_range_map_and_graph_report_transitive_origins() -> None:
    graph = ProvenanceGraph(
        (
            AncestryNode("compile", "compiler", origin=ByteOrigin.TOOLCHAIN),
            AncestryNode("metadata", "declared", origin=ByteOrigin.CERTIFIED_METADATA),
            AncestryNode("reference", "reference", origin=ByteOrigin.ORACLE),
            AncestryNode("link", "link", parents=("compile", "metadata")),
            AncestryNode("legacy", "install", parents=("link", "reference")),
        )
    )
    artifact = ArtifactRangeMap(
        "image",
        12,
        (
            RangeAncestry(ByteRange(0, 8), "link"),
            RangeAncestry(ByteRange(8, 12), "legacy"),
        ),
    )

    assert graph.origins_for(artifact, ByteRange(0, 8)) == {
        ByteOrigin.TOOLCHAIN,
        ByteOrigin.CERTIFIED_METADATA,
    }
    assert graph.has_clean_origin(artifact, ByteRange(0, 8))
    assert graph.has_oracle_ancestry(artifact)
    assert not graph.has_clean_origin(artifact)
    assert [node.id for node in graph.trace("legacy")] == [
        "compile",
        "metadata",
        "link",
        "reference",
        "legacy",
    ]


def test_range_map_requires_complete_exact_coverage() -> None:
    with pytest.raises(ProvenanceError, match="gap"):
        ArtifactRangeMap("object", 10, (RangeAncestry(ByteRange(1, 10), "compile"),))
    with pytest.raises(ProvenanceError, match="overlap"):
        ArtifactRangeMap(
            "object",
            10,
            (
                RangeAncestry(ByteRange(0, 7), "compile"),
                RangeAncestry(ByteRange(6, 10), "compile"),
            ),
        )


def test_graph_rejects_missing_parents_and_cycles() -> None:
    with pytest.raises(ProvenanceError, match="missing parents"):
        ProvenanceGraph((AncestryNode("child", "copy", parents=("missing",)),))
    with pytest.raises(ProvenanceError, match="cycle"):
        ProvenanceGraph(
            (
                AncestryNode("left", "copy", parents=("right",)),
                AncestryNode("right", "copy", parents=("left",)),
            )
        )


def test_digest_helpers_validate_size_and_content(tmp_path: Path) -> None:
    path = tmp_path / "artifact.bin"
    path.write_bytes(b"proof")
    expected = digest_bytes(b"proof")

    assert digest_file(path, chunk_size=2) == expected
    validate_artifact_digest(path, expected_digest=expected, expected_size=5)
    with pytest.raises(ProvenanceError, match="size drift"):
        validate_artifact_digest(path, expected_digest=expected, expected_size=4)
    with pytest.raises(ProvenanceError, match="digest drift"):
        validate_artifact_digest(path, expected_digest="0" * 64)
