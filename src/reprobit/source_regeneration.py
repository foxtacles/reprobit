"""Reviewed regeneration of source-derived authority after admitted source edits.

``rbit source lock`` refuses to bless stale pins: when an admitted source file
changes, every reviewed record that derived digests from that file must be
regenerated, not repinned.  This module implements that regeneration for the
record families whose derivations are fully mechanical:

* ``source_overlay_graph`` outputs — the clean digest, clean size, and the
  effective digest of the re-rendered overlay output;
* ``donor_source_overlay`` renderings — the proof-carried clean and rendered
  digests, and the intervention's rendering identity over the merged claim;
* translation-unit ``source_digest`` pins in the build plan and in
  translation-unit intervention documents.

Every proposed digest is recomputed by re-running the same renderer the
verifier uses, with every anchor resolved against the current bytes; an anchor
that no longer resolves aborts the whole plan.  Nothing is deleted, no
validator is bypassed, and the rewritten tree must still pass ``rbit source
lock`` and a from-scratch ``rbit verify`` — regeneration only proposes pins
that those gates then prove.  A digest of a changed file that survives in any
document at a location this module does not understand also aborts the plan,
so an unknown pin family can never ride along silently.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from reprobit.project_loader import load_project
from reprobit.strict_json import canonical_json, strict_loads
from reprobit.transactions import CASTransaction, TransactionResult

_SOURCE_OVERLAY_FAMILY = "source_overlay_graph"
_DONOR_OVERLAY_FAMILY = "donor_source_overlay"


class SourceRegenerationError(ValueError):
    """Regeneration cannot propose a provable replacement for a stale pin."""


@dataclass(frozen=True, slots=True)
class RegenerationChange:
    """One recorded field replacement inside one committed document."""

    document: str
    location: str
    before: str
    after: str


@dataclass(frozen=True, slots=True)
class RegenerationPlan:
    """A reviewed set of document rewrites plus the exact bytes they assume."""

    changes: tuple[RegenerationChange, ...]
    documents: Mapping[str, bytes]
    document_preimages: Mapping[str, str]
    control_preimages: Mapping[str, str | None]
    authority_directories: Mapping[str, tuple[str, ...]]
    read_sources: Mapping[str, str]

    @property
    def changed_documents(self) -> tuple[str, ...]:
        return tuple(sorted({change.document for change in self.changes}))


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _legacy_identity(value: object) -> str:
    """Hash the historical, stable indented JSON identity claim."""

    return _digest((json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode())


class _SourceReader:
    """Read project-relative source files once, remembering the exact bytes."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._cache: dict[str, bytes] = {}
        self._digests: dict[str, str] = {}

    def read(self, relative: str, *, wanted_by: str) -> bytes:
        cached = self._cache.get(relative)
        if cached is not None:
            return cached
        try:
            from reprobit.source_lock import SourceLockError, receipt_source_input

            _size, digest, data = receipt_source_input(self._root, relative, capture=True)
        except SourceLockError as exc:
            raise SourceRegenerationError(f"{wanted_by} cannot read {relative!r}: {exc}") from exc
        assert data is not None
        self._cache[relative] = data
        self._digests[relative] = digest.value
        return data

    @property
    def digests(self) -> dict[str, str]:
        return dict(self._digests)


def _parameter_map(intervention: dict[str, Any]) -> dict[str, Any]:
    parameters = intervention.get("parameters")
    if not isinstance(parameters, list):
        return {}
    values: dict[str, Any] = {}
    for field in parameters:
        if isinstance(field, dict) and isinstance(field.get("name"), str):
            values[field["name"]] = field.get("value")
    return values


def _set_parameter(intervention: dict[str, Any], name: str, value: Any) -> None:
    for field in intervention.get("parameters", []):
        if isinstance(field, dict) and field.get("name") == name:
            field["value"] = value
            return
    raise SourceRegenerationError(f"intervention parameter is missing: {name!r}")


def _document_paths(root: Path, relative: str) -> tuple[Path, ...]:
    directory = root / relative
    if not directory.is_dir():
        return ()
    return tuple(sorted(directory.rglob("*.json"), key=lambda item: item.as_posix()))


def _render_single(
    declaration: dict[str, Any],
    clean: bytes,
    *,
    context: str,
) -> tuple[str, int, bytes]:
    from reprobit.classic.overlay_document import render_classic_overlay_proposal

    try:
        result = render_classic_overlay_proposal([declaration], {str(declaration["path"]): clean})
    except ValueError as exc:
        raise SourceRegenerationError(f"{context} cannot be re-rendered: {exc}") from exc
    receipt = result.receipts[0]
    return receipt.output_digest, receipt.output_size, result.outputs[receipt.path]


_RENDERING_PIN = re.compile(r"^renderings\[(\d+)]\.(?:clean|rendered)_sha256$")


def _surviving_digest_binding(
    document: Any,
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
    documents: Mapping[str, Any],
    digests: frozenset[str],
    *,
    donor_paths: Mapping[str, tuple[str, ...]],
    intervention_sources: Mapping[str, str],
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
                            document,
                            ancestors,
                            key,
                            trail,
                            donor_paths=donor_paths,
                            intervention_sources=intervention_sources,
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

    for name, document in documents.items():
        index_document(name, document)
    return {digest: tuple(occurrences) for digest, occurrences in found.items()}


def plan_source_regeneration(project_root: Path | str) -> RegenerationPlan:
    """Propose pin regenerations for every stale mechanical derivation."""

    root = Path(project_root).resolve(strict=True)
    config_relative = "reprobit.toml"
    config_path = root / config_relative
    config_data = config_path.read_bytes()
    spec = load_project(root)
    if config_path.read_bytes() != config_data:
        raise SourceRegenerationError("reprobit.toml changed while regeneration was planned")
    reader = _SourceReader(root)
    changes: list[RegenerationChange] = []
    updated: dict[str, Any] = {}

    intervention_paths = _document_paths(root, spec.layout.interventions)
    proof_paths = _document_paths(root, spec.layout.proofs)
    authority_directories = {
        spec.layout.interventions: tuple(
            sorted(
                (
                    path.relative_to(root / spec.layout.interventions).as_posix()
                    for path in intervention_paths
                ),
                key=lambda item: (item.casefold(), item),
            )
        ),
        spec.layout.proofs: tuple(
            sorted(
                (path.relative_to(root / spec.layout.proofs).as_posix() for path in proof_paths),
                key=lambda item: (item.casefold(), item),
            )
        ),
    }
    documents: dict[str, Any] = {}
    document_preimages: dict[str, str] = {}
    control_preimages: dict[str, str | None] = {config_relative: _digest(config_data)}
    for document_path in (*intervention_paths, *proof_paths):
        name = document_path.relative_to(root).as_posix()
        data = document_path.read_bytes()
        documents[name] = strict_loads(data)
        document_preimages[name] = _digest(data)
    plan_relative = spec.layout.build_plan
    plan_path = root / plan_relative
    if plan_path.is_file():
        data = plan_path.read_bytes()
        documents[plan_relative] = strict_loads(data)
        document_preimages[plan_relative] = _digest(data)
    else:
        control_preimages[plan_relative] = None

    donor_paths: dict[str, tuple[str, ...]] = {}
    intervention_sources: dict[str, str] = {}
    for document in documents.values():
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
                intervention_sources[identifier] = donor_source
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
                donor_paths[identifier] = paths

    def record(document: str, location: str, before: str, after: str) -> None:
        if before == after:
            return
        changes.append(RegenerationChange(document, location, before, after))
        updated[document] = documents[document]

    stale_paths: dict[str, str] = {}
    stale_digest_paths: dict[str, set[str]] = {}

    def bind_stale(digest: object, path: str) -> None:
        if isinstance(digest, str) and len(digest) == 64:
            stale_digest_paths.setdefault(digest, set()).add(path)

    # Pass A: project-level source overlays own the effective text of their
    # outputs.  Re-render each stale output and propose clean/size/effective.
    effective_by_path: dict[str, str] = {}
    effective_bytes_by_path: dict[str, bytes] = {}
    canonical_operations_by_path: dict[str, tuple[dict[str, Any], ...]] = {}
    for name, document in documents.items():
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
                context = f"overlay output {path!r}"
                operations = output.get("ops")
                if not isinstance(operations, list) or any(
                    not isinstance(operation, dict) for operation in operations
                ):
                    raise SourceRegenerationError(f"{context} has malformed operations")
                canonical_operations_by_path[path] = tuple(operations)
                if "clean" not in output:
                    # Generated-only outputs have no clean input on disk; their
                    # effective bytes derive from generators alone and cannot
                    # go stale under a source edit.
                    effective_by_path.setdefault(path, str(output.get("effective")))
                    continue
                current = reader.read(path, wanted_by=f"{name} {context}")
                current_digest = _digest(current)
                if current_digest == output.get("clean"):
                    effective_by_path.setdefault(path, str(output.get("effective")))
                    continue
                declaration = dict(output)
                declaration["clean"] = current_digest
                declaration["size"] = len(current)
                new_effective, new_size, rendered_bytes = _render_single(
                    declaration, current, context=context
                )
                effective_bytes_by_path[path] = rendered_bytes
                stale_paths[path] = str(output["clean"])
                bind_stale(output.get("clean"), path)
                if output.get("effective") != new_effective:
                    bind_stale(output.get("effective"), path)
                record(name, f"{context} clean", str(output["clean"]), current_digest)
                record(name, f"{context} effective", str(output["effective"]), new_effective)
                if output.get("size") != new_size:
                    record(name, f"{context} size", str(output.get("size")), str(new_size))
                output["clean"] = current_digest
                output["effective"] = new_effective
                output["size"] = new_size
                effective_by_path[path] = new_effective

    # Pass B: donor-private overlays carry their clean and rendered digests in
    # proof expected values; the intervention identity covers the merged claim.
    receipts_by_intervention: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for name, document in documents.items():
        if not isinstance(document, dict):
            continue
        for observation in document.get("expected_observations", []) or []:
            if isinstance(observation, dict) and isinstance(
                observation.get("intervention_id"), str
            ):
                receipts_by_intervention.setdefault(observation["intervention_id"], []).append(
                    (name, observation)
                )

    for name, document in documents.items():
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
            receipts = receipts_by_intervention.get(identifier, [])
            expected_receipts = [
                (proof_name, observation)
                for proof_name, observation in receipts
                if isinstance(observation.get("expected_values"), dict)
            ]
            if len(expected_receipts) != 1:
                raise SourceRegenerationError(
                    f"donor overlay {identifier!r} requires exactly one proof "
                    f"receipt with expected values, found {len(expected_receipts)}"
                )
            proof_name, observation = expected_receipts[0]
            expected_values = observation["expected_values"]
            merged: list[dict[str, Any]] = []
            donor_changed = False
            for index, rendering in enumerate(renderings):
                if not isinstance(rendering, dict):
                    raise SourceRegenerationError(
                        f"donor overlay {identifier!r} rendering {index} is malformed"
                    )
                clean_key = f"renderings[{index}].clean_sha256"
                rendered_key = f"renderings[{index}].rendered_sha256"
                if clean_key not in expected_values or rendered_key not in expected_values:
                    raise SourceRegenerationError(
                        f"donor overlay {identifier!r} rendering {index} carries no "
                        "proof-pinned digests; its claim form is not regenerable here"
                    )
                path = str(rendering.get("path"))
                context = f"{name} donor {identifier} rendering {path!r}"
                current = reader.read(path, wanted_by=context)
                current_digest = _digest(current)
                pinned_clean = str(expected_values[clean_key])
                pinned_rendered = str(expected_values[rendered_key])
                if current_digest != pinned_clean:
                    operations = rendering.get("operations")
                    if not isinstance(operations, list) or any(
                        not isinstance(operation, dict) for operation in operations
                    ):
                        raise SourceRegenerationError(f"{context} has malformed operations")
                    rendered_operations = list(operations)
                    replay = values.get("canonical_overlay_replay")
                    if replay is not None:
                        if replay != "owning_translation_unit_v1":
                            raise SourceRegenerationError(
                                f"{context} has an unsupported canonical replay policy"
                            )
                        if index == 0:
                            canonical = canonical_operations_by_path.get(path)
                            if canonical is None:
                                raise SourceRegenerationError(
                                    f"{context} replays a canonical overlay output that "
                                    "no source overlay declares"
                                )
                            rendered_operations = [*canonical, *rendered_operations]
                    declaration = {
                        "path": path,
                        "clean": current_digest,
                        "effective": pinned_rendered,
                        "ops": rendered_operations,
                    }
                    new_rendered, _size, _bytes = _render_single(
                        declaration, current, context=context
                    )
                    stale_paths[path] = pinned_clean
                    bind_stale(pinned_clean, path)
                    if pinned_rendered != new_rendered:
                        bind_stale(pinned_rendered, path)
                    record(
                        proof_name,
                        f"{identifier} {clean_key}",
                        pinned_clean,
                        current_digest,
                    )
                    record(
                        proof_name,
                        f"{identifier} {rendered_key}",
                        pinned_rendered,
                        new_rendered,
                    )
                    expected_values[clean_key] = current_digest
                    expected_values[rendered_key] = new_rendered
                    pinned_clean = current_digest
                    pinned_rendered = new_rendered
                    donor_changed = True
                merged.append(
                    {
                        **rendering,
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
                        bind_stale(pinned_identity, rendering_path)
                record(
                    name,
                    f"{identifier} rendering_identity_sha256",
                    pinned_identity,
                    identity,
                )
                _set_parameter(intervention, "rendering_identity_sha256", identity)

    # Pass C: translation-unit source digests pin the effective text of the
    # unit's primary source — the overlay-rendered bytes when an overlay owns
    # the path, the clean bytes otherwise.
    def expected_source_digest(source: str, *, wanted_by: str) -> str:
        overlaid = effective_by_path.get(source)
        if overlaid is not None:
            return overlaid
        return _digest(reader.read(source, wanted_by=wanted_by))

    for name, document in documents.items():
        if not isinstance(document, dict) or name == plan_relative:
            continue
        source = document.get("source")
        digest_field = document.get("source_digest")
        if not isinstance(source, str) or not isinstance(digest_field, dict):
            continue
        expected = expected_source_digest(source, wanted_by=f"{name} source_digest")
        before = str(digest_field.get("value"))
        if before != expected:
            stale_paths.setdefault(source, before)
            bind_stale(before, source)
            record(name, f"source_digest ({source})", before, expected)
            digest_field["value"] = expected

    plan_document = documents.get(plan_relative)
    if isinstance(plan_document, dict):
        for unit in plan_document.get("translation_units", []) or []:
            if not isinstance(unit, dict):
                continue
            source = str(unit.get("source"))
            digest_field = unit.get("source_digest")
            if not isinstance(digest_field, dict):
                continue
            context = f"unit {unit.get('id')}"
            expected = expected_source_digest(source, wanted_by=f"{plan_relative} {context}")
            before = str(digest_field.get("value"))
            if before != expected:
                stale_paths.setdefault(source, before)
                bind_stale(before, source)
                record(plan_relative, f"{context} source_digest ({source})", before, expected)
                digest_field["value"] = expected

    # Pass D: declaration-carrier donors render generated declarations into
    # the effective text of their translation unit and pin the rendered bytes
    # (and, for special-seat families, content witnesses around the seats).
    from reprobit.classic_donors import (
        DonorSourceError,
        derive_special_seat_proof,
        render_declaration_carrier_source,
    )
    from reprobit.schema import (
        ClassicProofReceipt,
        ClassicRecipeIntervention,
        ClassicRecipeRole,
    )

    _DONOR_SOURCE_PIN_NAMES = frozenset(
        {"rendered_source_sha256", "donor_effective_source_sha256", "seat_proof"}
    )

    def effective_bytes_for(source: str, *, wanted_by: str) -> bytes:
        rendered = effective_bytes_by_path.get(source)
        if rendered is not None:
            return rendered
        if source in effective_by_path:
            raise SourceRegenerationError(
                f"{wanted_by} needs the effective bytes of {source!r}, but its "
                "overlay output was not re-rendered in this plan"
            )
        return reader.read(source, wanted_by=wanted_by)

    for name, document in documents.items():
        if not isinstance(document, dict) or name == plan_relative:
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
                raise SourceRegenerationError(
                    f"{name} donor {intervention.get('id')} has an invalid donor_source"
                )
            if source not in stale_paths:
                continue
            identifier = str(intervention.get("id"))
            context = f"{name} donor {identifier}"
            effective = effective_bytes_for(source, wanted_by=context)
            candidate = json.loads(json.dumps(intervention))
            try:
                if "seat_proof" in pinned_names:
                    _set_parameter(candidate, "seat_proof", derive_special_seat_proof(effective))
                if "donor_effective_source_sha256" in pinned_names:
                    _set_parameter(candidate, "donor_effective_source_sha256", _digest(effective))
                typed = ClassicRecipeIntervention.model_validate_json(canonical_json(candidate))
                typed_receipts = tuple(
                    ClassicProofReceipt.model_validate_json(canonical_json(observation))
                    for _proof_name, observation in receipts_by_intervention.get(identifier, [])
                )
                rendered = render_declaration_carrier_source(typed, typed_receipts, effective)
            except (DonorSourceError, ValueError) as exc:
                raise SourceRegenerationError(f"{context} cannot be re-rendered: {exc}") from exc

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
                bind_stale(before_value, source)
                record(
                    name,
                    f"{identifier} {parameter_name}",
                    json.dumps(before_value, sort_keys=True)
                    if not isinstance(before_value, str)
                    else before_value,
                    json.dumps(after_value, sort_keys=True)
                    if not isinstance(after_value, str)
                    else after_value,
                )
                _set_parameter(intervention, parameter_name, after_value)

    # Pass E: typed source-refactor proofs may pin supporting headers in
    # nested ``{path, source_sha256, ...}`` witnesses.  The whole-file digest
    # is only the mechanical identity of bytes inspected by independent range
    # pins and the closed semantic validator.  Enumerate those witness seats
    # explicitly; never infer a source pin from an arbitrary nested object.
    refactor_witness_paths: dict[str, tuple[tuple[str, ...], ...]] = {
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

    def source_refactor_witness(
        proof: dict[str, Any],
        trail: tuple[str, ...],
        *,
        context: str,
    ) -> dict[str, Any]:
        current: Any = proof
        for key in trail:
            if not isinstance(current, dict) or key not in current:
                raise SourceRegenerationError(
                    f"{context} lacks its declared {'.'.join(trail)} witness"
                )
            current = current[key]
        if not isinstance(current, dict):
            raise SourceRegenerationError(f"{context} has a malformed {'.'.join(trail)} witness")
        return current

    def refresh_source_refactor_witness(
        witness: dict[str, Any],
        *,
        document_name: str,
        intervention_id: str,
        proof_kind: str,
        trail: tuple[str, ...],
    ) -> None:
        path = witness.get("path")
        pinned = witness.get("source_sha256")
        context = f"{document_name} {intervention_id} target_source_refactor {'.'.join(trail)}"
        if not isinstance(path, str) or not isinstance(pinned, str):
            raise SourceRegenerationError(f"{context} has malformed source identity")
        current = reader.read(path, wanted_by=context)
        current_digest = _digest(current)
        if current_digest == pinned:
            return
        stale_paths.setdefault(path, pinned)
        bind_stale(pinned, path)
        location = f"{intervention_id} {proof_kind} {'.'.join(trail)}"
        record(
            document_name,
            f"{location} source_sha256 ({path})",
            pinned,
            current_digest,
        )
        witness["source_sha256"] = current_digest
        if "source_size" in witness and witness.get("source_size") != len(current):
            record(
                document_name,
                f"{location} source_size ({path})",
                str(witness.get("source_size")),
                str(len(current)),
            )
            witness["source_size"] = len(current)

    for name, document in documents.items():
        if not isinstance(document, dict) or name == plan_relative:
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
                raise SourceRegenerationError(
                    f"{name} source-refactor intervention {identifier!r} is invalid: {exc}"
                ) from exc
            if typed.role is not ClassicRecipeRole.FUNCTION or not isinstance(raw_proof, dict):
                raise SourceRegenerationError(
                    f"{name} source-refactor intervention {identifier!r} has an "
                    "invalid role or proof"
                )
            proof_kind = raw_proof.get("kind")
            if not isinstance(proof_kind, str):
                raise SourceRegenerationError(
                    f"{name} source-refactor intervention {identifier!r} has no typed proof kind"
                )
            for trail in refactor_witness_paths.get(proof_kind, ()):
                refresh_source_refactor_witness(
                    source_refactor_witness(
                        raw_proof,
                        trail,
                        context=f"{name} source-refactor intervention {identifier!r}",
                    ),
                    document_name=name,
                    intervention_id=identifier,
                    proof_kind=proof_kind,
                    trail=trail,
                )

    # Completeness sweep: a changed path's old digest may legitimately be the
    # current digest of a different, byte-identical source. Bind every exact
    # surviving value to its declared path so that duplicate source bytes do
    # not look stale, while an unknown or still-changed binding remains fatal.
    surviving = _digest_occurrence_index(
        documents,
        frozenset(stale_digest_paths),
        donor_paths=donor_paths,
        intervention_sources=intervention_sources,
    )
    for old, changed_paths in sorted(stale_digest_paths.items()):
        for name, binding in surviving[old]:
            if binding is not None and binding not in changed_paths:
                continue
            detail = "an unknown source" if binding is None else repr(binding)
            raise SourceRegenerationError(
                f"stale digest {old} survives in {name} bound to {detail} at a "
                "location this regeneration does not understand; regenerate "
                "that record with its own adapter first"
            )

    return RegenerationPlan(
        changes=tuple(changes),
        documents=MappingProxyType(
            {name: canonical_json(document) for name, document in updated.items()}
        ),
        document_preimages=MappingProxyType(dict(document_preimages)),
        control_preimages=MappingProxyType(control_preimages),
        authority_directories=MappingProxyType(authority_directories),
        read_sources=MappingProxyType(reader.digests),
    )


def apply_source_regeneration(
    project_root: Path | str,
    plan: RegenerationPlan,
) -> TransactionResult | None:
    """Write a regeneration plan transactionally against the bytes it read."""

    if not plan.changes:
        return None
    root = Path(project_root).resolve(strict=True)
    transaction = CASTransaction(root)
    for name in plan.changed_documents:
        transaction.write(
            name,
            plan.documents[name],
            expected_sha256=plan.document_preimages[name],
        )
    for name, digest in sorted(plan.document_preimages.items()):
        if name not in plan.documents:
            transaction.assert_unchanged(name, expected_sha256=digest)
    for name, control_digest in sorted(plan.control_preimages.items()):
        transaction.assert_unchanged(name, expected_sha256=control_digest)
    for relative, members in sorted(plan.authority_directories.items()):
        transaction.assert_json_members(relative, expected_members=members)
    for path, source_digest in sorted(plan.read_sources.items()):
        transaction.assert_unchanged(path, expected_sha256=source_digest)
    return transaction.commit()


__all__ = [
    "RegenerationChange",
    "RegenerationPlan",
    "SourceRegenerationError",
    "apply_source_regeneration",
    "plan_source_regeneration",
]
