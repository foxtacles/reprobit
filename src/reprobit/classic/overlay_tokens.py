"""Bounded token indexes, anchor resolution, and render-session reuse."""

from __future__ import annotations

import hashlib
import re
from array import array
from collections import OrderedDict, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from threading import RLock
from types import MappingProxyType

from reprobit.artifacts import digest_bytes
from reprobit.classic.overlay_types import (
    ClassicOverlayAnchorReceipt,
    ClassicOverlayRenderSessionStats,
    _Anchor,
    _Output,
)
from reprobit.classic.overlay_validation import (
    _BOUNDARIES,
    _digest,
    _fail,
    _integer,
    _keys,
    _object,
)

_TOKEN_RE = re.compile(
    r"//[^\n]*|/\*.*?\*/|"
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
    r"[A-Za-z_]\w*|0[xX][0-9A-Fa-f]+|"
    r"\d+(?:\.\d*)?(?:[eE][+-]?\d+)?[A-Za-z]*|"
    r"::|->\*|->|\.\*|<<=|>>=|==|!=|<=|>=|\+\+|--|&&|\|\||"
    r"<<|>>|\+=|-=|\*=|/=|%=|&=|\|=|\^=|##|\.\.\.|[^\s]",
    re.DOTALL,
)
_ANNOTATION_COMMENT_RE = re.compile(
    r"//\s*(?:FUNCTION|GLOBAL|VTABLE|STRING|LIBRARY|SYNTHETIC|TODO|OFFSET|SIZE)\b"
)


@dataclass(frozen=True, slots=True)
class _TokenIndex:
    """Significant-token bytes and offsets without retaining the clean source."""

    token_blob: bytes
    blob_starts: array[int]
    source_starts: array[int]
    source_ends: array[int]

    @property
    def token_count(self) -> int:
        return len(self.source_starts)

    @property
    def retained_size(self) -> int:
        return (
            len(self.token_blob)
            + self.blob_starts.buffer_info()[1] * self.blob_starts.itemsize
            + self.source_starts.buffer_info()[1] * self.source_starts.itemsize
            + self.source_ends.buffer_info()[1] * self.source_ends.itemsize
        )

    def blob_end(self, index: int) -> int:
        if index + 1 < self.token_count:
            return self.blob_starts[index + 1] - 1
        return len(self.token_blob)


_SourceIndexKey = tuple[int, str]
_AnchorRequest = tuple[int, int, tuple[str, ...]]
_AnchorMatchKey = tuple[int, int, str]
_AnchorBatchKey = tuple[_SourceIndexKey, tuple[_AnchorRequest, ...]]


class ClassicOverlayRenderSession:
    """Bounded, thread-safe token/anchor reuse for one caller invocation.

    Cache keys contain only byte counts and content digests.  Values contain a
    compact significant-token stream, source offsets, and matches for the
    exact anchor digests requested by a render.  Raw clean/effective source
    bytes and unrequested seat digests are never retained.  Closing the
    session deterministically releases all derived indexes.
    """

    def __init__(
        self,
        *,
        maximum_index_bytes: int = 16 * 1024 * 1024,
        maximum_index_entries: int = 256,
        maximum_anchor_batches: int = 512,
        maximum_anchor_requests: int = 8192,
    ) -> None:
        if (
            type(maximum_index_bytes) is not int
            or type(maximum_index_entries) is not int
            or type(maximum_anchor_batches) is not int
            or type(maximum_anchor_requests) is not int
            or maximum_index_bytes < 0
            or maximum_index_entries < 0
            or maximum_anchor_batches < 0
            or maximum_anchor_requests < 0
        ):
            raise ValueError("classic overlay render-session bounds must be non-negative integers")
        self._maximum_index_bytes = maximum_index_bytes
        self._maximum_index_entries = maximum_index_entries
        self._maximum_anchor_batches = maximum_anchor_batches
        self._maximum_anchor_requests = maximum_anchor_requests
        self._indexes: OrderedDict[_SourceIndexKey, _TokenIndex] = OrderedDict()
        self._index_bytes = 0
        self._anchor_batches: OrderedDict[
            _AnchorBatchKey, Mapping[_AnchorMatchKey, tuple[int, ...]]
        ] = OrderedDict()
        self._anchor_request_count = 0
        self._lock = RLock()
        self._closed = False
        self._token_index_builds = 0
        self._token_index_hits = 0
        self._anchor_batch_builds = 0
        self._anchor_batch_hits = 0
        self._anchor_windows_hashed = 0

    def __enter__(self) -> ClassicOverlayRenderSession:
        with self._lock:
            if self._closed:
                raise ValueError("classic overlay render session is closed")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        """Release every invocation-local derived index."""

        with self._lock:
            self._indexes.clear()
            self._anchor_batches.clear()
            self._index_bytes = 0
            self._anchor_request_count = 0
            self._closed = True

    @property
    def stats(self) -> ClassicOverlayRenderSessionStats:
        with self._lock:
            return ClassicOverlayRenderSessionStats(
                token_index_builds=self._token_index_builds,
                token_index_hits=self._token_index_hits,
                anchor_batch_builds=self._anchor_batch_builds,
                anchor_batch_hits=self._anchor_batch_hits,
                anchor_windows_hashed=self._anchor_windows_hashed,
                retained_token_indexes=len(self._indexes),
                retained_index_bytes=self._index_bytes,
                retained_anchor_batches=len(self._anchor_batches),
                retained_anchor_requests=self._anchor_request_count,
            )

    def significant_tokens(self, data: bytes) -> tuple[tuple[str, int, int], ...]:
        """Lex immutable bytes through this invocation's bounded compact index."""

        if type(data) is not bytes:
            raise ValueError("classic overlay token input must be immutable bytes")
        with self._lock:
            self._require_open()
            _key, index = self._token_index(data, digest_bytes(data))
            return _tokens_from_index(index)

    def _require_open(self) -> None:
        if self._closed:
            raise ValueError("classic overlay render session is closed")

    def _token_index(self, data: bytes, content_digest: str) -> tuple[_SourceIndexKey, _TokenIndex]:
        key = (len(data), content_digest)
        with self._lock:
            self._require_open()
            cached = self._indexes.get(key)
            if cached is not None:
                self._indexes.move_to_end(key)
                self._token_index_hits += 1
                return key, cached
            index = _build_token_index(data)
            self._token_index_builds += 1
            if (
                self._maximum_index_entries
                and self._maximum_index_bytes
                and index.retained_size <= self._maximum_index_bytes
            ):
                while self._indexes and (
                    len(self._indexes) >= self._maximum_index_entries
                    or self._index_bytes + index.retained_size > self._maximum_index_bytes
                ):
                    _discarded_key, discarded = self._indexes.popitem(last=False)
                    self._index_bytes -= discarded.retained_size
                if self._index_bytes + index.retained_size <= self._maximum_index_bytes:
                    self._indexes[key] = index
                    self._index_bytes += index.retained_size
            return key, index

    def _anchor_matches(
        self,
        data: bytes,
        content_digest: str,
        requests: Mapping[tuple[int, int], set[str]],
    ) -> tuple[_TokenIndex, Mapping[_AnchorMatchKey, tuple[int, ...]]]:
        normalized_requests = tuple(
            (before, after, tuple(sorted(digests)))
            for (before, after), digests in sorted(requests.items())
        )
        with self._lock:
            self._require_open()
            source_key, index = self._token_index(data, content_digest)
            batch_key = (source_key, normalized_requests)
            cached = self._anchor_batches.get(batch_key)
            if cached is not None:
                self._anchor_batches.move_to_end(batch_key)
                self._anchor_batch_hits += 1
                return index, cached
            matches, windows_hashed = _requested_anchor_matches(index, normalized_requests)
            self._anchor_batch_builds += 1
            self._anchor_windows_hashed += windows_hashed
            frozen = MappingProxyType(matches)
            request_count = sum(len(digests) for _before, _after, digests in normalized_requests)
            if (
                self._maximum_anchor_batches
                and self._maximum_anchor_requests
                and request_count <= self._maximum_anchor_requests
            ):
                while self._anchor_batches and (
                    len(self._anchor_batches) >= self._maximum_anchor_batches
                    or self._anchor_request_count + request_count > self._maximum_anchor_requests
                ):
                    discarded_key, _discarded = self._anchor_batches.popitem(last=False)
                    self._anchor_request_count -= sum(
                        len(digests) for _before, _after, digests in discarded_key[1]
                    )
                self._anchor_batches[batch_key] = frozen
                self._anchor_request_count += request_count
            return index, frozen


def _tokens(data: bytes) -> tuple[tuple[str, int, int], ...]:
    """Return significant tokens without retaining source bytes globally."""

    text = data.decode("latin1")
    result: list[tuple[str, int, int]] = []
    for match in _TOKEN_RE.finditer(text):
        token = match.group(0)
        if token.startswith(("//", "/*")):
            continue
        result.append((token, match.start(), match.end()))
    return tuple(result)


def _build_token_index(data: bytes) -> _TokenIndex:
    text = data.decode("latin1")
    token_blob = bytearray()
    blob_starts = array("I")
    source_starts = array("I")
    source_ends = array("I")
    for match in _TOKEN_RE.finditer(text):
        token = match.group(0)
        if token.startswith(("//", "/*")):
            continue
        if blob_starts:
            token_blob.append(0)
        blob_starts.append(len(token_blob))
        source_starts.append(match.start())
        source_ends.append(match.end())
        token_blob.extend(token.encode("latin1"))
    if any(offset.itemsize != 4 for offset in (blob_starts, source_starts, source_ends)):
        raise RuntimeError("classic overlay compact offset storage is not 32-bit")
    return _TokenIndex(
        token_blob=bytes(token_blob),
        blob_starts=blob_starts,
        source_starts=source_starts,
        source_ends=source_ends,
    )


def _tokens_from_index(index: _TokenIndex) -> tuple[tuple[str, int, int], ...]:
    blob = index.token_blob
    return tuple(
        (
            blob[index.blob_starts[token_index] : index.blob_end(token_index)].decode("latin1"),
            index.source_starts[token_index],
            index.source_ends[token_index],
        )
        for token_index in range(index.token_count)
    )


def _token_sequence_digest(tokens: Sequence[str]) -> str:
    return digest_bytes("\0".join(tokens).encode("latin1"))


def _seat_digest_from_index(
    index: _TokenIndex,
    token_boundary: int,
    before_count: int,
    after_count: int,
) -> str:
    digest = hashlib.sha256()
    token_blob = memoryview(index.token_blob)
    if before_count:
        first = token_boundary - before_count
        last = token_boundary - 1
        digest.update(token_blob[index.blob_starts[first] : index.blob_end(last)])
        digest.update(b"\0<SEAT>\0" if after_count else b"\0<SEAT>")
    else:
        digest.update(b"<SEAT>\0" if after_count else b"<SEAT>")
    if after_count:
        last = token_boundary + after_count - 1
        digest.update(token_blob[index.blob_starts[token_boundary] : index.blob_end(last)])
    return digest.hexdigest()


def _requested_anchor_matches(
    index: _TokenIndex,
    requests: Sequence[_AnchorRequest],
) -> tuple[dict[_AnchorMatchKey, tuple[int, ...]], int]:
    """Hash each required seat once and retain only requested digest matches."""

    retained: dict[_AnchorMatchKey, list[int]] = {}
    windows_hashed = 0
    for before_count, after_count, requested_digests in requests:
        requested = set(requested_digests)
        upper = index.token_count - after_count
        for token_boundary in range(before_count, upper + 1):
            windows_hashed += 1
            context_digest = _seat_digest_from_index(
                index, token_boundary, before_count, after_count
            )
            if context_digest not in requested:
                continue
            key = (before_count, after_count, context_digest)
            matches = retained.setdefault(key, [])
            if len(matches) < 2:
                matches.append(token_boundary)
    return {key: tuple(value) for key, value in retained.items()}, windows_hashed


def _anchor(value: object, context: str) -> _Anchor:
    item = _object(value, context)
    _keys(
        item,
        {"ctx"},
        context,
        optional={"b", "a", "at", "line_before", "line_after"},
    )
    before = _integer(item.get("b", 32), f"{context}.b", minimum=0, maximum=32)
    after = _integer(item.get("a", 32), f"{context}.a", minimum=0, maximum=32)
    if not before and not after:
        _fail(f"{context} cannot match an empty context")
    raw_boundary = item.get("at")
    if raw_boundary is None:
        boundary = "after_newline"
    elif isinstance(raw_boundary, str) and raw_boundary in _BOUNDARIES:
        boundary = _BOUNDARIES[raw_boundary]
    else:
        _fail(f"{context}.at is unsupported")
    before_line = after_line = None
    if boundary == "after_newline":
        before_line = _digest(item.get("line_before"), f"{context}.line_before")
        after_line = _digest(item.get("line_after"), f"{context}.line_after")
    elif "line_before" in item or "line_after" in item:
        _fail(f"{context} line digests belong to after-newline seats only")
    return _Anchor(
        _digest(item.get("ctx"), f"{context}.ctx"), before, after, boundary, before_line, after_line
    )


def _seat_lines(data: bytes, offset: int) -> tuple[bytes, bytes]:
    before_lines = data[:offset].splitlines()
    after_lines = data[offset:].splitlines()
    return (before_lines[-1] if before_lines else b"", after_lines[0] if after_lines else b"")


@dataclass(frozen=True, slots=True)
class _AnchorResolver:
    data: bytes
    tokens: _TokenIndex
    matches: Mapping[_AnchorMatchKey, tuple[int, ...]]


def _anchor_requests(output: _Output) -> dict[tuple[int, int], set[str]]:
    requests: dict[tuple[int, int], set[str]] = defaultdict(set)
    for operation in output.operations:
        for anchor in (operation.start, operation.end):
            if anchor is not None:
                requests[(anchor.before_count, anchor.after_count)].add(anchor.context_digest)
    return requests


def _anchor_resolver(
    data: bytes,
    output: _Output,
    session: ClassicOverlayRenderSession,
) -> _AnchorResolver | None:
    requests = _anchor_requests(output)
    if not requests:
        return None
    if output.clean_digest is None:
        _fail(f"generated-only overlay output {output.path!r} contains contextual anchors")
    tokens, matches = session._anchor_matches(data, output.clean_digest, requests)
    return _AnchorResolver(data, tokens, matches)


def _resolve_anchor(
    resolver: _AnchorResolver, anchor: _Anchor, context: str, role: str
) -> tuple[int, ClassicOverlayAnchorReceipt]:
    data = resolver.data
    matches = resolver.tokens
    candidates = list(
        resolver.matches.get((anchor.before_count, anchor.after_count, anchor.context_digest), ())
    )
    if len(candidates) > 1:
        _fail(f"{context} is ambiguous")
    if not candidates:
        _fail(f"{context} is missing from its clean input")
    index = candidates[0]
    lower = matches.source_ends[index - 1] if index else 0
    upper = matches.source_starts[index] if index < matches.token_count else len(data)
    if lower > upper:
        _fail(f"{context} token boundary is invalid")
    if anchor.boundary == "file_start":
        if lower != 0:
            _fail(f"{context} is not at file start")
        offset = 0
    elif anchor.boundary == "file_end":
        if upper != len(data):
            _fail(f"{context} is not at file end")
        offset = len(data)
    elif anchor.boundary == "after_previous_token":
        offset = lower
    elif anchor.boundary == "before_next_token":
        offset = upper
    else:
        selected: list[int] = []
        for position in range(lower, upper):
            if data[position : position + 1] != b"\n":
                continue
            before_line, after_line = _seat_lines(data, position + 1)
            if (
                digest_bytes(before_line) == anchor.before_line_digest
                and digest_bytes(after_line) == anchor.after_line_digest
            ):
                selected.append(position + 1)
        if len(selected) != 1:
            _fail(f"{context} has no unique after-newline structural seat")
        offset = selected[0]
    return offset, ClassicOverlayAnchorReceipt(role, anchor.context_digest, index, offset)
