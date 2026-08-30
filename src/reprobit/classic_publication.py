"""One rollback-safe publication boundary for classic target output sets."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
from pathlib import Path, PurePosixPath

from reprobit.secure_path_contracts import (
    SecureFileSnapshot,
    SecurePathError,
)
from reprobit.secure_paths import (
    atomic_publish_new_relative,
    atomic_publish_new_relative_from_stream,
    atomic_publish_relative_if_current,
    hold_relative_file_set,
    read_relative_file,
    remove_published_relative,
    windows_attributes_are_basic_restorable,
)
from reprobit.state_lock import AdvisoryFileLock, StateError


class ClassicPublicationError(RuntimeError):
    """A complete classic output set could not be published safely."""


@dataclass(frozen=True, slots=True)
class ClassicPublicationRequest:
    """One member of a coordinated target/PDB publication set."""

    owner_id: str
    kind: str
    producer_step: str
    relative: str
    payload: bytes
    mode: int | None = None
    windows_attributes: int | None = None


@dataclass(frozen=True, slots=True)
class ClassicPublishedOutput:
    """One held final output and whether this invocation replaced it."""

    request: ClassicPublicationRequest
    snapshot: SecureFileSnapshot
    changed: bool


@contextmanager
def _publication_transaction(state_root: Path) -> Iterator[None]:
    marker = b"reprobit-warm-target-publication-v1\n"
    relative = "warm-target-publication.lock"
    try:
        snapshot = atomic_publish_new_relative(state_root, relative, marker)
    except SecurePathError:
        try:
            payload, snapshot = read_relative_file(state_root, relative)
        except SecurePathError as exc:
            raise ClassicPublicationError(f"classic publication lock is unsafe: {exc}") from exc
        if payload != marker:
            raise ClassicPublicationError("classic publication lock marker is invalid") from None
    try:
        lock = AdvisoryFileLock(snapshot.path, create=False)
    except (OSError, StateError) as exc:
        raise ClassicPublicationError(f"classic publication lock cannot be opened: {exc}") from exc
    with lock:
        try:
            payload = lock.read_locked(maximum=len(marker))
        except (OSError, StateError) as exc:
            raise ClassicPublicationError(
                f"classic publication lock changed while acquiring it: {exc}"
            ) from exc
        if payload != marker:
            raise ClassicPublicationError("classic publication lock changed while acquiring it")
        yield


@contextmanager
def publish_classic_output_set(
    project_root: Path,
    state_root: Path,
    requests: Sequence[ClassicPublicationRequest],
    *,
    before_commit: Callable[[], None] | None = None,
) -> Iterator[tuple[ClassicPublishedOutput, ...]]:
    """Compare-and-swap a complete output set, rolling it all back on failure."""

    if not requests:
        raise ClassicPublicationError("classic publication set is empty")
    folded = [request.relative.replace("\\", "/").casefold() for request in requests]
    if len(folded) != len(set(folded)):
        raise ClassicPublicationError("classic publication paths collide under DOS folding")
    if any(type(request.payload) is not bytes for request in requests):
        raise ClassicPublicationError("classic publication payload is not immutable bytes")

    committed: list[tuple[ClassicPublicationRequest, SecureFileSnapshot]] = []
    prepared: list[
        tuple[
            ClassicPublicationRequest,
            bytes | None,
            SecureFileSnapshot | None,
        ]
    ] = []
    try:
        with _publication_transaction(state_root):
            if before_commit is not None:
                before_commit()
            for request in requests:
                destination = project_root.joinpath(
                    *PurePosixPath(request.relative.replace("\\", "/")).parts
                )
                prior_payload: bytes | None = None
                prior: SecureFileSnapshot | None = None
                if os.path.lexists(destination):
                    try:
                        prior_payload, prior = read_relative_file(
                            project_root,
                            request.relative,
                        )
                    except SecurePathError as exc:
                        raise ClassicPublicationError(
                            f"classic {request.kind} {request.owner_id!r} prior output "
                            f"is unsafe: {exc}"
                        ) from exc
                    if os.name == "posix" and stat.S_IMODE(prior.mode) & ~0o777:
                        raise ClassicPublicationError(
                            f"classic {request.kind} {request.owner_id!r} has "
                            "unsupported special mode bits"
                        )
                    if os.name == "nt" and not windows_attributes_are_basic_restorable(
                        prior.windows_attributes
                    ):
                        raise ClassicPublicationError(
                            f"classic {request.kind} {request.owner_id!r} has "
                            "non-restorable Windows attributes"
                        )
                prepared.append((request, prior_payload, prior))

            published: list[ClassicPublishedOutput] = []
            for request, prior_payload, prior in prepared:
                metadata_matches = prior is not None and (
                    (
                        os.name == "posix"
                        and (request.mode is None or stat.S_IMODE(prior.mode) == request.mode)
                    )
                    or (
                        os.name == "nt"
                        and (
                            request.windows_attributes is None
                            or prior.windows_attributes == request.windows_attributes
                        )
                    )
                )
                changed = prior_payload != request.payload or not metadata_matches
                if not changed:
                    current_payload, snapshot = read_relative_file(
                        project_root,
                        request.relative,
                    )
                    if current_payload != request.payload or snapshot != prior:
                        raise ClassicPublicationError(
                            f"classic {request.kind} {request.owner_id!r} changed "
                            "before no-op publication"
                        )
                else:
                    snapshot = atomic_publish_relative_if_current(
                        project_root,
                        request.relative,
                        request.payload,
                        expected=prior,
                        mode=request.mode if os.name == "posix" else None,
                        windows_attributes=(
                            request.windows_attributes if os.name == "nt" else None
                        ),
                    )
                    committed.append((request, snapshot))
                if (
                    snapshot.digest.value != sha256(request.payload).hexdigest()
                    or snapshot.size != len(request.payload)
                    or (
                        os.name == "posix"
                        and request.mode is not None
                        and stat.S_IMODE(snapshot.mode) != request.mode
                    )
                    or (
                        os.name == "nt"
                        and request.windows_attributes is not None
                        and snapshot.windows_attributes != request.windows_attributes
                    )
                ):
                    raise ClassicPublicationError(
                        f"classic {request.kind} {request.owner_id!r} changed during publication"
                    )
                published.append(ClassicPublishedOutput(request, snapshot, changed))

            expected = {item.request.relative: item.snapshot for item in published}
            with hold_relative_file_set(project_root, expected) as held:
                held_outputs = tuple(
                    ClassicPublishedOutput(
                        item.request,
                        held[item.request.relative],
                        item.changed,
                    )
                    for item in published
                )
                committed = [(request, held[request.relative]) for request, _snapshot in committed]
                yield held_outputs
    except BaseException as publication_error:
        rollback_errors: list[str] = []
        for request, snapshot in reversed(committed):
            try:
                removed = remove_published_relative(
                    project_root,
                    request.relative,
                    expected=snapshot,
                )
                if not removed:
                    continue
                prior_entry = next(
                    (
                        item
                        for item in prepared
                        if item[0].relative.casefold() == request.relative.casefold()
                    ),
                    None,
                )
                if prior_entry is None or prior_entry[1] is None or prior_entry[2] is None:
                    continue
                prior_payload = prior_entry[1]
                prior_snapshot = prior_entry[2]
                restored = atomic_publish_new_relative_from_stream(
                    project_root,
                    request.relative,
                    BytesIO(prior_payload),
                    mode=(stat.S_IMODE(prior_snapshot.mode) if os.name == "posix" else None),
                    windows_attributes=(
                        prior_snapshot.windows_attributes if os.name == "nt" else None
                    ),
                    expected_digest=prior_snapshot.digest,
                    expected_size=prior_snapshot.size,
                )
                if (
                    restored.digest != prior_snapshot.digest
                    or restored.size != prior_snapshot.size
                    or (
                        os.name == "posix"
                        and stat.S_IMODE(restored.mode) != stat.S_IMODE(prior_snapshot.mode)
                    )
                    or (
                        os.name == "nt"
                        and restored.windows_attributes != prior_snapshot.windows_attributes
                    )
                ):
                    raise ClassicPublicationError(
                        f"classic {request.kind} rollback changed prior bytes"
                    )
            except BaseException as rollback_error:
                rollback_errors.append(f"{request.owner_id}/{request.kind}: {rollback_error}")
        if rollback_errors:
            publication_error.add_note(
                "classic publication rollback also failed: " + "; ".join(rollback_errors)
            )
        if isinstance(publication_error, (KeyboardInterrupt, SystemExit)):
            raise
        if isinstance(publication_error, ClassicPublicationError):
            raise
        raise ClassicPublicationError(
            f"classic output set could not be published safely: {publication_error}"
        ) from publication_error


__all__ = [
    "ClassicPublicationError",
    "ClassicPublicationRequest",
    "ClassicPublishedOutput",
    "publish_classic_output_set",
]
