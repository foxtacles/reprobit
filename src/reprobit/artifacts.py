"""Artifact digests and byte-range provenance.

The high-level schema models describe whole artifacts.  This module supplies the
lower-level range map used when an output is assembled from more than one
producer.  Ranges are deliberately half-open: that makes adjacency and complete
coverage checks unambiguous.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from pathlib import Path

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/+-]*$")


class ProvenanceError(ValueError):
    """Raised when provenance is incomplete or internally inconsistent."""


class ByteOrigin(StrEnum):
    """Root origins that can contribute bytes to an artifact."""

    TOOLCHAIN = "toolchain"
    DECLARED_EXTERNAL = "declared_external"
    CERTIFIED_METADATA = "certified_metadata"
    ORACLE = "oracle"
    UNKNOWN = "unknown"


@dataclass(frozen=True, order=True, slots=True)
class ByteRange:
    """A non-empty half-open byte range ``[start, end)``."""

    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 0:
            raise ProvenanceError("range start cannot be negative")
        if self.end <= self.start:
            raise ProvenanceError("range end must be greater than start")

    @property
    def length(self) -> int:
        return self.end - self.start

    def contains(self, other: ByteRange) -> bool:
        return self.start <= other.start and other.end <= self.end

    def intersects(self, other: ByteRange) -> bool:
        return self.start < other.end and other.start < self.end

    def intersection(self, other: ByteRange) -> ByteRange | None:
        start = max(self.start, other.start)
        end = min(self.end, other.end)
        return ByteRange(start, end) if start < end else None


@dataclass(frozen=True, slots=True)
class AncestryNode:
    """One node in a byte-production DAG.

    A root has an explicit ``origin`` and no parents.  A transform has one or
    more parents and no direct origin.  Giving a transform a direct origin would
    make it impossible to tell which bytes were inherited, so it is rejected.
    """

    id: str
    operation: str
    parents: tuple[str, ...] = ()
    origin: ByteOrigin | None = None
    recipe_id: str | None = None
    metadata: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.id):
            raise ProvenanceError(f"invalid ancestry node id: {self.id!r}")
        if not _IDENTIFIER.fullmatch(self.operation):
            raise ProvenanceError(f"invalid ancestry operation: {self.operation!r}")
        if len(set(self.parents)) != len(self.parents):
            raise ProvenanceError(f"ancestry node {self.id!r} has duplicate parents")
        if self.parents and self.origin is not None:
            raise ProvenanceError("a transform node cannot also declare a root origin")
        if not self.parents and self.origin is None:
            raise ProvenanceError("an ancestry root must declare an origin")
        keys = [key for key, _ in self.metadata]
        if len(set(keys)) != len(keys):
            raise ProvenanceError(f"ancestry node {self.id!r} has duplicate metadata keys")


@dataclass(frozen=True, slots=True)
class RangeAncestry:
    """Assign one provenance DAG node to an output byte range."""

    span: ByteRange
    node_id: str

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.node_id):
            raise ProvenanceError(f"invalid ancestry node id: {self.node_id!r}")


@dataclass(frozen=True, slots=True)
class ArtifactRangeMap:
    """Complete, non-overlapping byte ancestry for one artifact."""

    artifact_id: str
    size: int
    ranges: tuple[RangeAncestry, ...]

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.artifact_id):
            raise ProvenanceError(f"invalid artifact id: {self.artifact_id!r}")
        if self.size < 0:
            raise ProvenanceError("artifact size cannot be negative")
        if self.size == 0:
            if self.ranges:
                raise ProvenanceError("an empty artifact cannot have ancestry ranges")
            return
        if not self.ranges:
            raise ProvenanceError("a non-empty artifact needs complete range ancestry")
        cursor = 0
        for item in self.ranges:
            if item.span.start != cursor:
                problem = "overlap" if item.span.start < cursor else "gap"
                raise ProvenanceError(
                    f"artifact {self.artifact_id!r} has a range {problem} at offset {cursor}"
                )
            if item.span.end > self.size:
                raise ProvenanceError("ancestry range extends beyond the artifact")
            cursor = item.span.end
        if cursor != self.size:
            raise ProvenanceError(
                f"artifact {self.artifact_id!r} ancestry ends at {cursor}, expected {self.size}"
            )

    def covering(self, span: ByteRange) -> tuple[RangeAncestry, ...]:
        if span.end > self.size:
            raise ProvenanceError("requested range extends beyond the artifact")
        return tuple(item for item in self.ranges if item.span.intersects(span))


@dataclass(slots=True)
class ProvenanceGraph:
    """Validated ancestry DAG with range-aware origin queries."""

    nodes: Iterable[AncestryNode]
    _nodes: dict[str, AncestryNode] = field(init=False, repr=False)
    _origin_cache: dict[str, frozenset[ByteOrigin]] = field(
        init=False, default_factory=dict, repr=False
    )

    def __post_init__(self) -> None:
        indexed: dict[str, AncestryNode] = {}
        for node in self.nodes:
            if node.id in indexed:
                raise ProvenanceError(f"duplicate ancestry node id: {node.id!r}")
            indexed[node.id] = node
        for node in indexed.values():
            missing = set(node.parents).difference(indexed)
            if missing:
                raise ProvenanceError(
                    f"ancestry node {node.id!r} has missing parents: {sorted(missing)!r}"
                )
        self._nodes = indexed
        self.nodes = tuple(indexed.values())
        self._validate_acyclic()

    def __iter__(self) -> Iterator[AncestryNode]:
        return iter(self._nodes.values())

    def __getitem__(self, node_id: str) -> AncestryNode:
        try:
            return self._nodes[node_id]
        except KeyError as error:
            raise ProvenanceError(f"unknown ancestry node: {node_id!r}") from error

    def _validate_acyclic(self) -> None:
        visiting: set[str] = set()
        complete: set[str] = set()

        def visit(node_id: str, trail: tuple[str, ...]) -> None:
            if node_id in complete:
                return
            if node_id in visiting:
                cycle = " -> ".join((*trail, node_id))
                raise ProvenanceError(f"ancestry cycle: {cycle}")
            visiting.add(node_id)
            node = self._nodes[node_id]
            for parent in node.parents:
                visit(parent, (*trail, node_id))
            visiting.remove(node_id)
            complete.add(node_id)

        for node_id in self._nodes:
            visit(node_id, ())

    def root_origins(self, node_id: str) -> frozenset[ByteOrigin]:
        """Return all root byte origins reachable from ``node_id``."""

        if node_id in self._origin_cache:
            return self._origin_cache[node_id]
        node = self[node_id]
        if node.origin is not None:
            origins = frozenset((node.origin,))
        else:
            origins = frozenset(
                origin for parent in node.parents for origin in self.root_origins(parent)
            )
        self._origin_cache[node_id] = origins
        return origins

    def origins_for(
        self, artifact: ArtifactRangeMap, span: ByteRange | None = None
    ) -> frozenset[ByteOrigin]:
        """Return roots contributing to an artifact or one of its subranges."""

        selected = artifact.ranges if span is None else artifact.covering(span)
        missing = {item.node_id for item in selected}.difference(self._nodes)
        if missing:
            raise ProvenanceError(
                f"artifact {artifact.artifact_id!r} references missing nodes: {sorted(missing)!r}"
            )
        return frozenset(
            origin for item in selected for origin in self.root_origins(item.node_id)
        )

    def has_oracle_ancestry(
        self, artifact: ArtifactRangeMap, span: ByteRange | None = None
    ) -> bool:
        return ByteOrigin.ORACLE in self.origins_for(artifact, span)

    def has_clean_origin(
        self, artifact: ArtifactRangeMap, span: ByteRange | None = None
    ) -> bool:
        origins = self.origins_for(artifact, span)
        return bool(origins) and origins <= {
            ByteOrigin.TOOLCHAIN,
            ByteOrigin.DECLARED_EXTERNAL,
            ByteOrigin.CERTIFIED_METADATA,
        }

    def trace(self, node_id: str) -> tuple[AncestryNode, ...]:
        """Return a stable parents-first ancestry explanation."""

        ordered: list[AncestryNode] = []
        seen: set[str] = set()

        def add(current: str) -> None:
            if current in seen:
                return
            node = self[current]
            for parent in node.parents:
                add(parent)
            seen.add(current)
            ordered.append(node)

        add(node_id)
        return tuple(ordered)


def digest_bytes(data: bytes | bytearray | memoryview) -> str:
    """Return a lowercase SHA-256 hex digest."""

    return sha256(data).hexdigest()


def digest_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    """Hash a file without loading it into memory."""

    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def validate_artifact_digest(
    path: Path, *, expected_digest: str, expected_size: int | None = None
) -> None:
    """Validate an artifact and raise :class:`ProvenanceError` on drift."""

    stat = path.stat()
    if expected_size is not None and stat.st_size != expected_size:
        raise ProvenanceError(
            f"artifact size drift for {path}: got {stat.st_size}, expected {expected_size}"
        )
    actual = digest_file(path)
    if actual != expected_digest.lower():
        raise ProvenanceError(
            f"artifact digest drift for {path}: got {actual}, expected {expected_digest.lower()}"
        )
