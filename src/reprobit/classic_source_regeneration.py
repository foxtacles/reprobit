"""Classic derivations for refreshing source-bound project authority.

This module is deliberately private to :mod:`reprobit.source_regeneration`.
The top-level module owns the immutable public plan, filesystem snapshot, and
compare-and-swap publication.  This module only mutates that snapshot in
memory by re-running the closed classic renderers and completeness checks.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Never, Protocol

from reprobit.classic_donors import (
    DonorSourceError,
    derive_special_seat_proof,
    render_declaration_carrier_source,
)
from reprobit.intervention_metadata import (
    ClassicRecipeRole,
)
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeIntervention,
)
from reprobit.strict_json import canonical_json

_SOURCE_OVERLAY_FAMILY = "source_overlay_graph"
_DONOR_OVERLAY_FAMILY = "donor_source_overlay"
_DONOR_SOURCE_PIN_NAMES = frozenset(
    {"rendered_source_sha256", "donor_effective_source_sha256", "seat_proof"}
)
_RENDERING_PIN = re.compile(r"^renderings\[(\d+)]\.(?:clean|rendered)_sha256$")
_REFACTOR_WITNESS_PATHS: Mapping[str, tuple[tuple[str, ...], ...]] = {
    "fixed_array_fill_loop_v1": (("array_declaration",),),
    "fixed_array_shuffle_pointer_countdown_v1": (
        ("semantic_witness", "owner_header"),
        ("semantic_witness", "base_header"),
        ("semantic_witness", "types_header"),
    ),
    "inclusive_extent_assignment_v1": (
        ("semantic_witness", "source_owner_header"),
        ("semantic_witness", "source_accessor_header"),
        ("semantic_witness", "extent_header"),
    ),
    "constructor_allocation_lift_v1": (("semantic_witness", "owner_header"),),
}


class _SourceReader(Protocol):
    def read(self, relative: str, *, wanted_by: str) -> bytes: ...

    def read_clean_preimage(self, relative: str, *, expected_sha256: str) -> bytes | None: ...


@dataclass(frozen=True, slots=True)
class _ClassicRegenerationChange:
    document: str
    location: str
    before: str
    after: str


@dataclass(frozen=True, slots=True)
class _ClassicRegenerationResult:
    changes: tuple[_ClassicRegenerationChange, ...]
    updated_documents: tuple[str, ...]


@dataclass(slots=True)
class _ClassicRegenerationContext:
    """Explicit mutable state shared by the closed classic derivation passes."""

    documents: dict[str, Any]
    plan_relative: str
    reader: _SourceReader
    error_type: type[ValueError]
    changes: list[_ClassicRegenerationChange] = field(default_factory=list)
    updated_documents: dict[str, None] = field(default_factory=dict)
    stale_paths: dict[str, str] = field(default_factory=dict)
    stale_digest_paths: dict[str, set[str]] = field(default_factory=dict)
    donor_paths: dict[str, tuple[str, ...]] = field(default_factory=dict)
    intervention_sources: dict[str, str] = field(default_factory=dict)
    receipts_by_intervention: dict[str, list[tuple[str, dict[str, Any]]]] = field(
        default_factory=dict
    )
    effective_by_path: dict[str, str] = field(default_factory=dict)
    effective_bytes_by_path: dict[str, bytes] = field(default_factory=dict)
    canonical_operations_by_path: dict[str, tuple[dict[str, Any], ...]] = field(
        default_factory=dict
    )

    def reject(self, message: str, *, cause: BaseException | None = None) -> Never:
        error = self.error_type(message)
        if cause is None:
            raise error
        raise error from cause

    def record(self, document: str, location: str, before: str, after: str) -> None:
        if before == after:
            return
        self.changes.append(_ClassicRegenerationChange(document, location, before, after))
        self.updated_documents.setdefault(document, None)

    def bind_stale(self, digest: object, path: str) -> None:
        if isinstance(digest, str) and len(digest) == 64:
            self.stale_digest_paths.setdefault(digest, set()).add(path)

    def expected_source_digest(self, source: str, *, wanted_by: str) -> str:
        overlaid = self.effective_by_path.get(source)
        if overlaid is not None:
            return overlaid
        return _digest(self.reader.read(source, wanted_by=wanted_by))

    def effective_bytes_for(self, source: str, *, wanted_by: str) -> bytes:
        rendered = self.effective_bytes_by_path.get(source)
        if rendered is not None:
            return rendered
        if source in self.effective_by_path:
            self.reject(
                f"{wanted_by} needs the effective bytes of {source!r}, but its "
                "overlay output was not re-rendered in this plan"
            )
        return self.reader.read(source, wanted_by=wanted_by)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _legacy_identity(value: object) -> str:
    """Hash the historical, stable indented JSON identity claim."""

    return _digest((json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode())


def _parameter_map(intervention: dict[str, Any]) -> dict[str, Any]:
    parameters = intervention.get("parameters")
    if not isinstance(parameters, list):
        return {}
    values: dict[str, Any] = {}
    for field_value in parameters:
        if isinstance(field_value, dict) and isinstance(field_value.get("name"), str):
            values[field_value["name"]] = field_value.get("value")
    return values


def _set_parameter(
    context: _ClassicRegenerationContext,
    intervention: dict[str, Any],
    name: str,
    value: Any,
) -> None:
    for field_value in intervention.get("parameters", []):
        if isinstance(field_value, dict) and field_value.get("name") == name:
            field_value["value"] = value
            return
    context.reject(f"intervention parameter is missing: {name!r}")


def _rewitness_rendering_operations(
    context: _ClassicRegenerationContext,
    operations: list[Any],
    clean: bytes,
    *,
    path: str,
    expected_clean: object,
) -> tuple[list[Any], list[tuple[str, str, str]]] | None:
    """Re-witness one operation list from its exact committed clean input."""

    from reprobit.classic.anchor_rewitness import rewitness_operations

    clean_preimage = None
    if any(
        isinstance(operation, Mapping)
        and any(
            isinstance(operation.get(key), Mapping)
            and operation[key].get("at") in {"before_token", "after_token"}
            for key in ("anchor", "from", "to")
        )
        for operation in operations
    ) and isinstance(expected_clean, str):
        clean_preimage = context.reader.read_clean_preimage(path, expected_sha256=expected_clean)
    return rewitness_operations(operations, clean, clean_preimage=clean_preimage)


def _render_or_rewitness(
    context: _ClassicRegenerationContext,
    declaration: dict[str, Any],
    clean: bytes,
    *,
    label: str,
    output: dict[str, Any],
    name: str,
) -> tuple[str, int, bytes]:
    """Render strictly; on anchor drift, re-witness once and render again.

    Anchor re-witnessing only rescues the mechanical drifts admitted by
    :mod:`reprobit.classic.anchor_rewitness` (blank lines at a recorded seat,
    a token move away from a seam whose literal seat pair still resolves
    uniquely, edited tokens beside a file-boundary seat, and an unchanged
    one-sided token window proved by the exact committed clean input).
    Anything else rejects with the original error.  A successful rescue
    persists the updated operations into the reviewed document and reports
    every changed witness digest.
    """

    from reprobit.classic.overlay_document import render_classic_overlay_proposal

    try:
        result = render_classic_overlay_proposal([declaration], {str(declaration["path"]): clean})
    except ValueError as exc:
        operations = declaration.get("ops")
        rescued = (
            _rewitness_rendering_operations(
                context,
                operations,
                clean,
                path=str(declaration["path"]),
                expected_clean=output.get("clean"),
            )
            if isinstance(operations, list)
            else None
        )
        if rescued is None:
            context.reject(f"{label} cannot be re-rendered: {exc}", cause=exc)
        updated_operations, witness_changes = rescued
        declaration["ops"] = updated_operations
        try:
            result = render_classic_overlay_proposal(
                [declaration], {str(declaration["path"]): clean}
            )
        except ValueError as retry_exc:
            context.reject(f"{label} cannot be re-rendered: {retry_exc}", cause=retry_exc)
        output["ops"] = updated_operations
        for location, old_digest, new_digest in witness_changes:
            context.record(name, f"{label} operation {location}", old_digest, new_digest)
    receipt = result.receipts[0]
    return receipt.output_digest, receipt.output_size, result.outputs[receipt.path]


def _operations_moved_output(output: dict[str, Any], clean: bytes, *, label: str) -> bool:
    """Report whether the reviewed operations no longer produce the pinned effective bytes.

    A source overlay's ``clean`` digest is unchanged when only its operations were
    edited (a retuned carrier knob, a widened forward run, a dropped declaration).
    Regeneration used to key staleness on the clean digest alone, so such an
    edit left the pinned ``effective`` digest and every downstream donor
    rendering stale until an operator invalidated the pin by hand.  Rendering
    the operations strictly against the unchanged clean bytes is cheap and
    decides the question exactly: a differing output digest means the operator
    changed what the overlay renders, and the pin must be re-derived.  An
    output that cannot be rendered on its own (a relocation whose partner
    output lives in another declaration) is reported as unmoved; the lock
    still renders every output together and refuses a broken one there.
    """

    from reprobit.classic.overlay_document import render_classic_overlay_proposal

    del label
    declaration = dict(output)
    declaration["clean"] = _digest(clean)
    declaration["size"] = len(clean)
    try:
        result = render_classic_overlay_proposal([declaration], {str(declaration["path"]): clean})
    except ValueError:
        return False
    return result.receipts[0].output_digest != output.get("effective")


def _surviving_digest_binding(
    ancestors: tuple[dict[str, Any], ...],
    key: str | int,
    trail: tuple[str | int, ...],
    *,
    donor_paths: Mapping[str, tuple[str, ...]],
    intervention_sources: Mapping[str, str],
) -> str | None:
    """Return the source path that owns one surviving source-derived digest."""

    if isinstance(key, str) and key in {"clean", "effective"}:
        for ancestor in reversed(ancestors):
            path = ancestor.get("path")
            if isinstance(path, str) and isinstance(ancestor.get("ops"), list):
                return path

    if isinstance(key, str):
        match = _RENDERING_PIN.fullmatch(key)
        if match is not None:
            for ancestor in reversed(ancestors):
                intervention_id = ancestor.get("intervention_id")
                if not isinstance(intervention_id, str):
                    continue
                paths = donor_paths.get(intervention_id)
                index = int(match.group(1))
                if paths is not None and index < len(paths):
                    return paths[index]

    if len(trail) >= 2 and trail[-2:] == ("source_digest", "value"):
        for ancestor in reversed(ancestors):
            source = ancestor.get("source")
            if isinstance(source, str):
                return source

    if key == "source_sha256" and ancestors:
        path = ancestors[-1].get("path")
        if isinstance(path, str):
            return path

    if key == "value" and ancestors:
        parameter_name = ancestors[-1].get("name")
        if parameter_name in {"donor_effective_source_sha256", "rendered_source_sha256"}:
            for ancestor in reversed(ancestors):
                candidate_id = ancestor.get("id")
                if not isinstance(candidate_id, str):
                    continue
                donor_source = intervention_sources.get(candidate_id)
                if donor_source is not None:
                    return donor_source
    return None


def _digest_occurrence_index(
    context: _ClassicRegenerationContext,
    digests: frozenset[str],
) -> dict[str, tuple[tuple[str, str | None], ...]]:
    """Index selected exact digest values in one walk over each document."""

    found: dict[str, list[tuple[str, str | None]]] = {digest: [] for digest in digests}

    def index_document(name: str, document: Any) -> None:
        def visit(
            value: Any,
            ancestors: tuple[dict[str, Any], ...],
            key: str | int,
            trail: tuple[str | int, ...],
        ) -> None:
            if isinstance(value, str) and value in digests:
                found[value].append(
                    (
                        name,
                        _surviving_digest_binding(
                            ancestors,
                            key,
                            trail,
                            donor_paths=context.donor_paths,
                            intervention_sources=context.intervention_sources,
                        ),
                    )
                )
                return
            if isinstance(value, dict):
                nested = (*ancestors, value)
                for child_key, child in value.items():
                    visit(child, nested, child_key, (*trail, child_key))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    visit(child, ancestors, index, (*trail, index))

        visit(document, (), "", ())

    for name, document in context.documents.items():
        index_document(name, document)
    return {digest: tuple(occurrences) for digest, occurrences in found.items()}


def _index_authority(context: _ClassicRegenerationContext) -> None:
    for name, document in context.documents.items():
        if not isinstance(document, dict):
            continue
        owning_source = document.get("source")
        for intervention in document.get("interventions", []) or []:
            if not isinstance(intervention, dict):
                continue
            identifier = intervention.get("id")
            values = _parameter_map(intervention)
            donor_source = values.get("donor_source", owning_source)
            if isinstance(identifier, str) and isinstance(donor_source, str):
                context.intervention_sources[identifier] = donor_source
            if intervention.get("family") != _DONOR_OVERLAY_FAMILY:
                continue
            renderings = values.get("renderings")
            if not isinstance(identifier, str) or not isinstance(renderings, list):
                continue
            paths = tuple(
                str(rendering.get("path"))
                for rendering in renderings
                if isinstance(rendering, dict) and isinstance(rendering.get("path"), str)
            )
            if len(paths) == len(renderings):
                context.donor_paths[identifier] = paths

        for observation in document.get("expected_observations", []) or []:
            if isinstance(observation, dict) and isinstance(
                observation.get("intervention_id"), str
            ):
                context.receipts_by_intervention.setdefault(
                    observation["intervention_id"], []
                ).append((name, observation))


def _refresh_source_overlays(context: _ClassicRegenerationContext) -> None:
    """Refresh canonical source-overlay clean, size, and effective pins."""

    for name, document in context.documents.items():
        if not isinstance(document, dict):
            continue
        for intervention in document.get("interventions", []) or []:
            if not isinstance(intervention, dict):
                continue
            if intervention.get("family") != _SOURCE_OVERLAY_FAMILY:
                continue
            values = _parameter_map(intervention)
            outputs = values.get("outputs")
            if not isinstance(outputs, list):
                continue
            for output in outputs:
                if not isinstance(output, dict):
                    continue
                path = str(output.get("path"))
                label = f"overlay output {path!r}"
                operations = output.get("ops")
                if not isinstance(operations, list) or any(
                    not isinstance(operation, dict) for operation in operations
                ):
                    context.reject(f"{label} has malformed operations")
                context.canonical_operations_by_path[path] = tuple(operations)
                if "clean" not in output:
                    context.effective_by_path.setdefault(path, str(output.get("effective")))
                    continue
                current = context.reader.read(path, wanted_by=f"{name} {label}")
                current_digest = _digest(current)
                if current_digest == output.get("clean") and not _operations_moved_output(
                    output, current, label=label
                ):
                    context.effective_by_path.setdefault(path, str(output.get("effective")))
                    continue
                declaration = dict(output)
                declaration["clean"] = current_digest
                declaration["size"] = len(current)
                new_effective, new_size, rendered_bytes = _render_or_rewitness(
                    context, declaration, current, label=label, output=output, name=name
                )
                context.canonical_operations_by_path[path] = tuple(output["ops"])
                context.effective_bytes_by_path[path] = rendered_bytes
                context.stale_paths[path] = str(output["clean"])
                if output.get("clean") != current_digest:
                    # An operation-only edit keeps the clean digest valid everywhere
                    # it is pinned; only a changed clean digest goes stale.
                    context.bind_stale(output.get("clean"), path)
                    context.record(name, f"{label} clean", str(output["clean"]), current_digest)
                if output.get("effective") != new_effective:
                    context.bind_stale(output.get("effective"), path)
                context.record(name, f"{label} effective", str(output["effective"]), new_effective)
                if output.get("size") != new_size:
                    context.record(name, f"{label} size", str(output.get("size")), str(new_size))
                output["clean"] = current_digest
                output["effective"] = new_effective
                output["size"] = new_size
                context.effective_by_path[path] = new_effective


def _prepare_donor_renderings(
    context: _ClassicRegenerationContext,
    renderings: list[Any],
    *,
    expected_values: dict[str, Any],
    values: Mapping[str, Any],
    document_name: str,
    identifier: str,
) -> list[dict[str, Any]]:
    """Read each rendering's clean bytes and resolve its operation list."""

    prepared: list[dict[str, Any]] = []
    for index, rendering in enumerate(renderings):
        if not isinstance(rendering, dict):
            context.reject(f"donor overlay {identifier!r} rendering {index} is malformed")
        clean_key = f"renderings[{index}].clean_sha256"
        rendered_key = f"renderings[{index}].rendered_sha256"
        if clean_key not in expected_values or rendered_key not in expected_values:
            context.reject(
                f"donor overlay {identifier!r} rendering {index} carries no "
                "proof-pinned digests; its claim form is not regenerable here"
            )
        path = str(rendering.get("path"))
        label = f"{document_name} donor {identifier} rendering {path!r}"
        operations = rendering.get("operations")
        if not isinstance(operations, list) or any(
            not isinstance(operation, dict) for operation in operations
        ):
            context.reject(f"{label} has malformed operations")
        rendered_operations = list(operations)
        operation_prefix: list[dict[str, Any]] = []
        replay = values.get("canonical_overlay_replay")
        if replay is not None:
            if replay != "owning_translation_unit_v1":
                context.reject(f"{label} has an unsupported canonical replay policy")
            if index == 0:
                canonical = context.canonical_operations_by_path.get(path)
                if canonical is None:
                    context.reject(
                        f"{label} replays a canonical overlay output that "
                        "no source overlay declares"
                    )
                operation_prefix = list(canonical)
                rendered_operations = [*operation_prefix, *rendered_operations]
        current = context.reader.read(path, wanted_by=label)
        prepared.append(
            {
                "rendering": rendering,
                "path": path,
                "label": label,
                "clean_key": clean_key,
                "rendered_key": rendered_key,
                "operations": rendered_operations,
                "operation_prefix": operation_prefix,
                "private_operations": operations,
                "current": current,
                "current_digest": _digest(current),
                "pinned_clean": str(expected_values[clean_key]),
                "pinned_rendered": str(expected_values[rendered_key]),
                "document_name": document_name,
            }
        )
    return prepared


def _render_donor_relocation_batch(
    context: _ClassicRegenerationContext,
    prepared: list[dict[str, Any]],
    *,
    label: str,
) -> dict[str, str]:
    """Render every rendering of one donor together and return its digests.

    Rendering is unconditional: a rendering's clean bytes may be unchanged
    while the owning overlay's canonical operations, or the rendering's own
    operations, were edited (a retuned carrier knob), and only a fresh render
    decides whether the pinned ``rendered_sha256`` still holds.  The renderer
    is deterministic and cheap, so an unchanged rendering simply reproduces
    its pin.  Rendering in one pass also serves source relocations: a
    relocation moves bytes between two of the donor's own renderings, the
    consumer's output depends on the producer's clean bytes, and the renderer
    rejects a producer whose consumer is absent from the same render.
    """

    from reprobit.classic.overlay_document import render_classic_overlay_proposal

    if not prepared:
        return {}

    clean_inputs = {item["path"]: item["current"] for item in prepared}

    def render(
        replacements: Mapping[int, list[Any]] | None = None,
    ) -> Any:
        declarations = [
            {
                "path": item["path"],
                "clean": item["current_digest"],
                "effective": item["pinned_rendered"],
                "ops": (
                    [*item["operation_prefix"], *replacements[index]]
                    if replacements is not None and index in replacements
                    else item["operations"]
                ),
            }
            for index, item in enumerate(prepared)
        ]
        return render_classic_overlay_proposal(declarations, clean_inputs)

    try:
        result = render()
    except ValueError as exc:
        replacements: dict[int, list[Any]] = {}
        witness_changes: dict[int, list[tuple[str, str, str]]] = {}
        for index, item in enumerate(prepared):
            rescued = _rewitness_rendering_operations(
                context,
                item["private_operations"],
                item["current"],
                path=item["path"],
                expected_clean=item["pinned_clean"],
            )
            if rescued is None:
                continue
            replacements[index], witness_changes[index] = rescued
        if not replacements:
            context.reject(f"{label} cannot be re-rendered: {exc}", cause=exc)
        try:
            # Keep every rendering in the retry so relocation producers and
            # consumers are validated as one closed donor batch.
            result = render(replacements)
        except ValueError as retry_exc:
            context.reject(f"{label} cannot be re-rendered: {retry_exc}", cause=retry_exc)
        for index, updated_operations in replacements.items():
            item = prepared[index]
            item["rendering"]["operations"] = updated_operations
            item["private_operations"] = updated_operations
            item["operations"] = [*item["operation_prefix"], *updated_operations]
            for location, old_digest, new_digest in witness_changes[index]:
                context.record(
                    item["document_name"],
                    f"{item['label']} operation {location}",
                    old_digest,
                    new_digest,
                )
    return {receipt.path: receipt.output_digest for receipt in result.receipts}


def _refresh_donor_overlays(context: _ClassicRegenerationContext) -> None:
    """Refresh donor-private overlay receipts and merged rendering identities."""

    for name, document in context.documents.items():
        if not isinstance(document, dict):
            continue
        for intervention in document.get("interventions", []) or []:
            if not isinstance(intervention, dict):
                continue
            if intervention.get("family") != _DONOR_OVERLAY_FAMILY:
                continue
            identifier = str(intervention.get("id"))
            values = _parameter_map(intervention)
            renderings = values.get("renderings")
            if not isinstance(renderings, list):
                continue
            receipts = context.receipts_by_intervention.get(identifier, [])
            expected_receipts = [
                (proof_name, observation)
                for proof_name, observation in receipts
                if isinstance(observation.get("expected_values"), dict)
            ]
            if len(expected_receipts) != 1:
                context.reject(
                    f"donor overlay {identifier!r} requires exactly one proof "
                    f"receipt with expected values, found {len(expected_receipts)}"
                )
            proof_name, observation = expected_receipts[0]
            expected_values = observation["expected_values"]
            merged: list[dict[str, Any]] = []
            donor_changed = False
            prepared = _prepare_donor_renderings(
                context,
                renderings,
                expected_values=expected_values,
                values=values,
                document_name=name,
                identifier=identifier,
            )
            # A source relocation deletes a range from one rendering and
            # inserts those same bytes into another, so the renderer checks
            # that every producer meets its consumer.  Rendering one file at a
            # time cannot satisfy that: the pair must be rendered together,
            # and a change to either file moves the relocated bytes.
            batch_digests = _render_donor_relocation_batch(
                context, prepared, label=f"{name} donor {identifier}"
            )
            for item in prepared:
                path = item["path"]
                pinned_clean = item["pinned_clean"]
                pinned_rendered = item["pinned_rendered"]
                current_digest = item["current_digest"]
                new_rendered = batch_digests.get(path)
                if new_rendered is None:
                    context.reject(f"{item['label']} was not rendered by its donor batch")
                if current_digest != pinned_clean:
                    context.stale_paths[path] = pinned_clean
                    context.bind_stale(pinned_clean, path)
                    context.record(
                        proof_name,
                        f"{identifier} {item['clean_key']}",
                        pinned_clean,
                        current_digest,
                    )
                    expected_values[item["clean_key"]] = current_digest
                    pinned_clean = current_digest
                    donor_changed = True
                if new_rendered is not None and new_rendered != pinned_rendered:
                    context.bind_stale(pinned_rendered, path)
                    context.record(
                        proof_name,
                        f"{identifier} {item['rendered_key']}",
                        pinned_rendered,
                        new_rendered,
                    )
                    expected_values[item["rendered_key"]] = new_rendered
                    pinned_rendered = new_rendered
                    donor_changed = True
                merged.append(
                    {
                        **item["rendering"],
                        "clean_sha256": pinned_clean,
                        "rendered_sha256": pinned_rendered,
                    }
                )
            if not donor_changed:
                continue
            claim: object = merged
            replay = values.get("canonical_overlay_replay")
            if "compiler_state_carrier" in values or replay is not None:
                wrapped: dict[str, Any] = {"renderings": merged}
                if "compiler_state_carrier" in values:
                    wrapped["compiler_state_carrier"] = values["compiler_state_carrier"]
                if replay is not None:
                    wrapped["canonical_overlay_replay"] = replay
                claim = wrapped
            identity = _legacy_identity(claim)
            pinned_identity = str(values.get("rendering_identity_sha256"))
            if identity != pinned_identity:
                for rendering in merged:
                    rendering_path = rendering.get("path")
                    if isinstance(rendering_path, str):
                        context.bind_stale(pinned_identity, rendering_path)
                context.record(
                    name,
                    f"{identifier} rendering_identity_sha256",
                    pinned_identity,
                    identity,
                )
                _set_parameter(context, intervention, "rendering_identity_sha256", identity)


def _refresh_translation_units(context: _ClassicRegenerationContext) -> None:
    """Refresh effective TU source digests in shards and the build plan."""

    for name, document in context.documents.items():
        if not isinstance(document, dict) or name == context.plan_relative:
            continue
        source = document.get("source")
        digest_field = document.get("source_digest")
        if not isinstance(source, str) or not isinstance(digest_field, dict):
            continue
        expected = context.expected_source_digest(source, wanted_by=f"{name} source_digest")
        before = str(digest_field.get("value"))
        if before != expected:
            context.stale_paths.setdefault(source, before)
            context.bind_stale(before, source)
            context.record(name, f"source_digest ({source})", before, expected)
            digest_field["value"] = expected

    plan_document = context.documents.get(context.plan_relative)
    if not isinstance(plan_document, dict):
        return
    for unit in plan_document.get("translation_units", []) or []:
        if not isinstance(unit, dict):
            continue
        source = str(unit.get("source"))
        digest_field = unit.get("source_digest")
        if not isinstance(digest_field, dict):
            continue
        label = f"unit {unit.get('id')}"
        expected = context.expected_source_digest(
            source, wanted_by=f"{context.plan_relative} {label}"
        )
        before = str(digest_field.get("value"))
        if before != expected:
            context.stale_paths.setdefault(source, before)
            context.bind_stale(before, source)
            context.record(
                context.plan_relative,
                f"{label} source_digest ({source})",
                before,
                expected,
            )
            digest_field["value"] = expected


def _refresh_declaration_carriers(context: _ClassicRegenerationContext) -> None:
    """Refresh declaration-carrier rendered source and seat witnesses."""

    for name, document in context.documents.items():
        if not isinstance(document, dict) or name == context.plan_relative:
            continue
        owning_source = document.get("source")
        if not isinstance(owning_source, str):
            continue
        for intervention in document.get("interventions", []) or []:
            if not isinstance(intervention, dict):
                continue
            values = _parameter_map(intervention)
            pinned_names = _DONOR_SOURCE_PIN_NAMES & values.keys()
            if not pinned_names:
                continue
            source = values.get("donor_source", owning_source)
            if not isinstance(source, str):
                context.reject(f"{name} donor {intervention.get('id')} has an invalid donor_source")
            if source not in context.stale_paths:
                continue
            identifier = str(intervention.get("id"))
            label = f"{name} donor {identifier}"
            effective = context.effective_bytes_for(source, wanted_by=label)
            candidate = json.loads(json.dumps(intervention))
            try:
                if "seat_proof" in pinned_names:
                    _set_parameter(
                        context, candidate, "seat_proof", derive_special_seat_proof(effective)
                    )
                if "donor_effective_source_sha256" in pinned_names:
                    _set_parameter(
                        context,
                        candidate,
                        "donor_effective_source_sha256",
                        _digest(effective),
                    )
                typed = ClassicRecipeIntervention.model_validate_json(canonical_json(candidate))
                typed_receipts = tuple(
                    ClassicProofReceipt.model_validate_json(canonical_json(observation))
                    for _proof_name, observation in context.receipts_by_intervention.get(
                        identifier, []
                    )
                )
                rendered = render_declaration_carrier_source(typed, typed_receipts, effective)
            except (DonorSourceError, ValueError) as exc:
                context.reject(f"{label} cannot be re-rendered: {exc}", cause=exc)

            replacements: dict[str, Any] = {}
            if "seat_proof" in pinned_names:
                replacements["seat_proof"] = _parameter_map(candidate)["seat_proof"]
            if "donor_effective_source_sha256" in pinned_names:
                replacements["donor_effective_source_sha256"] = _digest(effective)
            if "rendered_source_sha256" in values:
                replacements["rendered_source_sha256"] = _digest(rendered)
                if "rendered_source_size" in values:
                    replacements["rendered_source_size"] = len(rendered)
                if "rendered_source_line_count" in values:
                    replacements["rendered_source_line_count"] = rendered.count(b"\n")
            for parameter_name, after_value in replacements.items():
                before_value = values.get(parameter_name)
                if before_value == after_value:
                    continue
                context.bind_stale(before_value, source)
                context.record(
                    name,
                    f"{identifier} {parameter_name}",
                    json.dumps(before_value, sort_keys=True)
                    if not isinstance(before_value, str)
                    else before_value,
                    json.dumps(after_value, sort_keys=True)
                    if not isinstance(after_value, str)
                    else after_value,
                )
                _set_parameter(context, intervention, parameter_name, after_value)


def _refresh_source_identities(context: _ClassicRegenerationContext) -> None:
    """Re-pin same-function source identities on mechanically refreshed files.

    A ``same_function_source_identity`` pins the clean and effective digests
    of the file that carries the identified function alongside content-based
    range and carrier witnesses.  When regeneration has already re-rendered
    that file (an admitted mechanical edit), the two file-level digests are
    stale by definition; the range, carrier, and rendered-source pins witness
    content the edit did not touch and are still checked against actual bytes
    by the verifying rebuild.
    """

    stale_by_digest = {old: path for path, old in context.stale_paths.items()}
    for name, document in context.documents.items():
        if not isinstance(document, dict) or name == context.plan_relative:
            continue
        for intervention in document.get("interventions", []) or []:
            if not isinstance(intervention, dict):
                continue
            values = _parameter_map(intervention)
            identity = values.get("same_function_source_identity")
            if not isinstance(identity, dict):
                continue
            old_clean = identity.get("clean_source_sha256")
            path = stale_by_digest.get(old_clean) if isinstance(old_clean, str) else None
            if path is None:
                continue
            identifier = str(intervention.get("id"))
            label = f"{name} intervention {identifier} same_function_source_identity"
            current = context.reader.read(path, wanted_by=label)
            new_effective = context.effective_by_path.get(path)
            if new_effective is None:
                context.reject(f"{label} refreshed file {path!r} has no effective rendering")
            updated = dict(identity)
            updated["clean_source_sha256"] = _digest(current)
            updated["effective_source_sha256"] = new_effective
            for field_name in ("clean_source_sha256", "effective_source_sha256"):
                before_value = identity.get(field_name)
                if before_value == updated[field_name]:
                    continue
                context.bind_stale(before_value, path)
                context.record(
                    name,
                    f"{identifier} same_function_source_identity.{field_name}",
                    str(before_value),
                    str(updated[field_name]),
                )
            _set_parameter(context, intervention, "same_function_source_identity", updated)


def _source_refactor_witness(
    context: _ClassicRegenerationContext,
    proof: dict[str, Any],
    trail: tuple[str, ...],
    *,
    label: str,
) -> dict[str, Any]:
    current: Any = proof
    for key in trail:
        if not isinstance(current, dict) or key not in current:
            context.reject(f"{label} lacks its declared {'.'.join(trail)} witness")
        current = current[key]
    if not isinstance(current, dict):
        context.reject(f"{label} has a malformed {'.'.join(trail)} witness")
    return current


def _refresh_source_refactor_witness(
    context: _ClassicRegenerationContext,
    witness: dict[str, Any],
    *,
    document_name: str,
    intervention_id: str,
    proof_kind: str,
    trail: tuple[str, ...],
) -> None:
    path = witness.get("path")
    pinned = witness.get("source_sha256")
    label = f"{document_name} {intervention_id} target_source_refactor {'.'.join(trail)}"
    if not isinstance(path, str) or not isinstance(pinned, str):
        context.reject(f"{label} has malformed source identity")
    current = context.reader.read(path, wanted_by=label)
    current_digest = _digest(current)
    if current_digest == pinned:
        return
    context.stale_paths.setdefault(path, pinned)
    context.bind_stale(pinned, path)
    location = f"{intervention_id} {proof_kind} {'.'.join(trail)}"
    context.record(
        document_name,
        f"{location} source_sha256 ({path})",
        pinned,
        current_digest,
    )
    witness["source_sha256"] = current_digest
    if "source_size" in witness and witness.get("source_size") != len(current):
        context.record(
            document_name,
            f"{location} source_size ({path})",
            str(witness.get("source_size")),
            str(len(current)),
        )
        witness["source_size"] = len(current)


def _refresh_typed_witnesses(context: _ClassicRegenerationContext) -> None:
    """Refresh explicitly enumerated typed source-refactor witnesses."""

    for name, document in context.documents.items():
        if not isinstance(document, dict) or name == context.plan_relative:
            continue
        for intervention in document.get("interventions", []) or []:
            if not isinstance(intervention, dict):
                continue
            values = _parameter_map(intervention)
            raw_proof = values.get("target_source_refactor")
            if raw_proof is None:
                continue
            identifier = str(intervention.get("id"))
            try:
                typed = ClassicRecipeIntervention.model_validate_json(canonical_json(intervention))
            except ValueError as exc:
                context.reject(
                    f"{name} source-refactor intervention {identifier!r} is invalid: {exc}",
                    cause=exc,
                )
            if typed.role is not ClassicRecipeRole.FUNCTION or not isinstance(raw_proof, dict):
                context.reject(
                    f"{name} source-refactor intervention {identifier!r} has an "
                    "invalid role or proof"
                )
            proof_kind = raw_proof.get("kind")
            if not isinstance(proof_kind, str):
                context.reject(
                    f"{name} source-refactor intervention {identifier!r} has no typed proof kind"
                )
            for trail in _REFACTOR_WITNESS_PATHS.get(proof_kind, ()):
                _refresh_source_refactor_witness(
                    context,
                    _source_refactor_witness(
                        context,
                        raw_proof,
                        trail,
                        label=f"{name} source-refactor intervention {identifier!r}",
                    ),
                    document_name=name,
                    intervention_id=identifier,
                    proof_kind=proof_kind,
                    trail=trail,
                )


def _require_complete(context: _ClassicRegenerationContext) -> None:
    """Reject any stale digest not consumed by a known classic derivation."""

    surviving = _digest_occurrence_index(context, frozenset(context.stale_digest_paths))
    for old, changed_paths in sorted(context.stale_digest_paths.items()):
        for name, binding in surviving[old]:
            if binding is not None and binding not in changed_paths:
                continue
            detail = "an unknown source" if binding is None else repr(binding)
            context.reject(
                f"stale digest {old} survives in {name} bound to {detail} at a "
                "location this regeneration does not understand; regenerate "
                "that record with its own adapter first"
            )


def derive_classic_source_regeneration(
    *,
    documents: dict[str, Any],
    plan_relative: str,
    reader: _SourceReader,
    error_type: type[ValueError],
) -> _ClassicRegenerationResult:
    """Run every closed classic source-derived refresh against one snapshot."""

    context = _ClassicRegenerationContext(documents, plan_relative, reader, error_type)
    _index_authority(context)
    _refresh_source_overlays(context)
    _refresh_donor_overlays(context)
    _refresh_translation_units(context)
    _refresh_declaration_carriers(context)
    _refresh_source_identities(context)
    _refresh_typed_witnesses(context)
    _require_complete(context)
    return _ClassicRegenerationResult(
        tuple(context.changes),
        tuple(context.updated_documents),
    )


__all__ = ["derive_classic_source_regeneration"]
