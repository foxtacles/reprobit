"""Typed edits to classic intervention and proof authority in private staging."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from reprobit.authority_snapshot import AuthoritySnapshotError, json_authority_members
from reprobit.intervention_metadata import (
    ClassicRecipeFamily,
    ClassicRecipeRole,
)
from reprobit.model import Digest, is_identifier
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeIntervention,
    InterventionDocument,
    LegacyAllowlistEntry,
    LegacyOracleInstallIntervention,
    ProjectSpec,
    ProofDocument,
)
from reprobit.strict_json import canonical_json
from reprobit.transactions import CASTransaction


class ClassicAuthorityRepairError(RuntimeError):
    """A staged classic authority edit is ambiguous or broader than declared."""


DROPPABLE_MOVE_PARAMETERS = frozenset({"debug_representation_delta"})
_PROJECT_LAYOUT_GENERATORS = frozenset(
    {
        "class",
        "empty_class",
        "enum",
        "extern_run",
        "fwd",
        "fwd_run",
        "fwd_seq",
        "lines",
        "proto",
        "typedef",
    }
)


def _inert_project_generator(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    kind = value.get("k")
    if kind == "seq":
        items = value.get("items")
        return isinstance(items, list) and all(
            isinstance(item, dict)
            and _inert_project_generator(
                {key: child for key, child in item.items() if key != "line"}
            )
            for item in items
        )
    return kind in _PROJECT_LAYOUT_GENERATORS


def _same_project_generator_with_layout_delta(before: object, after: object) -> bool:
    """Admit only the small declaration/layout moves searched by repair."""

    if before == after:
        return True
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    kind = before.get("k")
    if kind != after.get("k") or kind not in _PROJECT_LAYOUT_GENERATORS | {"seq"}:
        return False
    if kind == "seq":
        before_items = before.get("items")
        after_items = after.get("items")
        if not isinstance(before_items, list) or not isinstance(after_items, list):
            return False
        if {key: value for key, value in before.items() if key not in {"items", "lines"}} != {
            key: value for key, value in after.items() if key not in {"items", "lines"}
        }:
            return False
        if not isinstance(before.get("lines"), int) or not isinstance(after.get("lines"), int):
            return False
        shared = min(len(before_items), len(after_items))
        for index in range(shared):
            before_item = before_items[index]
            after_item = after_items[index]
            if not isinstance(before_item, dict) or not isinstance(after_item, dict):
                return False
            if not isinstance(before_item.get("line"), int) or not isinstance(
                after_item.get("line"), int
            ):
                return False
            before_child = {key: value for key, value in before_item.items() if key != "line"}
            after_child = {key: value for key, value in after_item.items() if key != "line"}
            if not _same_project_generator_with_layout_delta(before_child, after_child):
                return False
        extras = before_items[shared:] or after_items[shared:]
        return all(
            isinstance(item, dict)
            and isinstance(item.get("line"), int)
            and not isinstance(item.get("line"), bool)
            and cast(int, item["line"]) > 0
            and _inert_project_generator(
                {key: value for key, value in item.items() if key != "line"}
            )
            for item in extras
        )
    if kind == "lines":
        return (
            isinstance(before.get("n"), int)
            and isinstance(after.get("n"), int)
            and {key: value for key, value in before.items() if key != "n"}
            == {key: value for key, value in after.items() if key != "n"}
        )
    if kind in {"extern_run", "fwd_run"}:
        return (
            isinstance(before.get("count"), int)
            and isinstance(after.get("count"), int)
            and {key: value for key, value in before.items() if key != "count"}
            == {key: value for key, value in after.items() if key != "count"}
        )
    if kind == "class":
        before_members = before.get("members")
        after_members = after.get("members")
        if (
            not isinstance(before_members, list)
            or not isinstance(after_members, list)
            or len(before_members) != len(after_members)
            or {key: value for key, value in before.items() if key != "members"}
            != {key: value for key, value in after.items() if key != "members"}
        ):
            return False
        for before_member, after_member in zip(before_members, after_members, strict=True):
            if not isinstance(before_member, dict) or not isinstance(after_member, dict):
                return False
            if before_member == after_member:
                continue
            if (
                "stem" not in before_member
                or not isinstance(before_member.get("count"), int)
                or not isinstance(after_member.get("count"), int)
                or {key: value for key, value in before_member.items() if key != "count"}
                != {key: value for key, value in after_member.items() if key != "count"}
            ):
                return False
        return True
    # Other declaration forms may be appended or removed, but their internal
    # identity is never edited by this authority type.
    return False


def _same_project_operations_with_layout_delta(before: object, after: object) -> bool:
    if not isinstance(before, list) or not isinstance(after, list):
        return False
    shared = min(len(before), len(after))
    for index in range(shared):
        before_operation = before[index]
        after_operation = after[index]
        if not isinstance(before_operation, dict) or not isinstance(after_operation, dict):
            return False
        if {key: value for key, value in before_operation.items() if key != "gen"} != {
            key: value for key, value in after_operation.items() if key != "gen"
        } or not _same_project_generator_with_layout_delta(
            before_operation.get("gen"), after_operation.get("gen")
        ):
            return False
    extras = before[shared:] or after[shared:]
    return all(
        isinstance(operation, dict)
        and operation.get("op") in {"insert", "append"}
        and _inert_project_generator(operation.get("gen"))
        for operation in extras
    )


@dataclass(frozen=True, slots=True)
class ClassicInterventionEdit:
    before: ClassicRecipeIntervention
    after: ClassicRecipeIntervention | None

    def __post_init__(self) -> None:
        if self.after is None:
            return
        try:
            after = ClassicRecipeIntervention.model_validate(
                self.after.model_dump(mode="python", warnings=False)
            )
        except ValueError as exc:
            raise ClassicAuthorityRepairError(
                f"intervention {self.before.id!r} replacement is invalid: {exc}"
            ) from exc
        object.__setattr__(self, "after", after)
        if (
            after.id != self.before.id
            or after.role is not self.before.role
            or after.family is not self.before.family
            or after.scope != self.before.scope
            or after.build_target != self.before.build_target
        ):
            raise ClassicAuthorityRepairError(
                f"intervention {self.before.id!r} replacement changes its identity or scope"
            )
        if after == self.before:
            raise ClassicAuthorityRepairError(
                f"intervention {self.before.id!r} replacement makes no change"
            )
        if self.before.role is not ClassicRecipeRole.DONOR:
            raise ClassicAuthorityRepairError(
                f"intervention {self.before.id!r} replacement is not a donor adjustment"
            )
        unchanged = after.model_copy(
            update={
                "parameters": self.before.parameters,
                "beneficiaries": self.before.beneficiaries,
            }
        )
        if unchanged != self.before:
            raise ClassicAuthorityRepairError(
                f"intervention {self.before.id!r} replacement changes fields outside "
                "donor parameters or beneficiaries"
            )


@dataclass(frozen=True, slots=True)
class ClassicProjectOverlayEdit:
    """Replace one source-overlay layout before normal pin regeneration."""

    before: ClassicRecipeIntervention
    after: ClassicRecipeIntervention

    def __post_init__(self) -> None:
        try:
            after = ClassicRecipeIntervention.model_validate(
                self.after.model_dump(mode="python", warnings=False)
            )
        except ValueError as exc:
            raise ClassicAuthorityRepairError(
                f"project overlay {self.before.id!r} replacement is invalid: {exc}"
            ) from exc
        object.__setattr__(self, "after", after)
        if (
            self.before.role is not ClassicRecipeRole.PROJECT
            or self.before.family is not ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
            or after.id != self.before.id
            or after.role is not self.before.role
            or after.family is not self.before.family
            or after.scope != self.before.scope
            or after.build_target != self.before.build_target
        ):
            raise ClassicAuthorityRepairError(
                f"project overlay {self.before.id!r} replacement changes its identity or scope"
            )
        if after == self.before:
            raise ClassicAuthorityRepairError(
                f"project overlay {self.before.id!r} replacement makes no change"
            )
        before_parameters = {field.name: field.value for field in self.before.parameters}
        after_parameters = {field.name: field.value for field in after.parameters}
        if (
            set(before_parameters) != set(after_parameters)
            or "outputs" not in before_parameters
            or any(
                before_parameters[name] != after_parameters[name]
                for name in before_parameters
                if name != "outputs"
            )
        ):
            raise ClassicAuthorityRepairError(
                f"project overlay {self.before.id!r} replacement changes fields outside outputs"
            )
        unchanged = after.model_copy(update={"parameters": self.before.parameters})
        if unchanged != self.before:
            raise ClassicAuthorityRepairError(
                f"project overlay {self.before.id!r} replacement changes fields outside parameters"
            )
        before_outputs = before_parameters["outputs"]
        after_outputs = after_parameters["outputs"]
        if not isinstance(before_outputs, list) or not isinstance(after_outputs, list):
            raise ClassicAuthorityRepairError(
                f"project overlay {self.before.id!r} outputs are not a list"
            )
        if [item.get("path") if isinstance(item, dict) else None for item in before_outputs] != [
            item.get("path") if isinstance(item, dict) else None for item in after_outputs
        ]:
            raise ClassicAuthorityRepairError(
                f"project overlay {self.before.id!r} changes output order or spelling"
            )
        before_by_path = {
            str(item.get("path")).casefold(): item
            for item in before_outputs
            if isinstance(item, dict) and isinstance(item.get("path"), str)
        }
        after_by_path = {
            str(item.get("path")).casefold(): item
            for item in after_outputs
            if isinstance(item, dict) and isinstance(item.get("path"), str)
        }
        if (
            len(before_by_path) != len(before_outputs)
            or len(after_by_path) != len(after_outputs)
            or set(before_by_path) != set(after_by_path)
        ):
            raise ClassicAuthorityRepairError(
                f"project overlay {self.before.id!r} changes its output universe"
            )
        changed = [path for path in before_by_path if before_by_path[path] != after_by_path[path]]
        if len(changed) != 1:
            raise ClassicAuthorityRepairError(
                f"project overlay {self.before.id!r} must change exactly one output"
            )
        path = changed[0]
        before_output = before_by_path[path]
        after_output = after_by_path[path]
        assert isinstance(before_output, dict) and isinstance(after_output, dict)
        if set(before_output) != set(after_output) or any(
            before_output[name] != after_output[name]
            for name in before_output
            if name not in {"ops", "effective", "size"}
        ):
            raise ClassicAuthorityRepairError(
                f"project overlay {self.before.id!r} changes output fields outside layout pins"
            )
        if before_output.get("ops") == after_output.get("ops"):
            raise ClassicAuthorityRepairError(
                f"project overlay {self.before.id!r} changes pins without a layout edit"
            )
        if not _same_project_operations_with_layout_delta(
            before_output.get("ops"), after_output.get("ops")
        ):
            raise ClassicAuthorityRepairError(
                f"project overlay {self.before.id!r} changes non-layout source operations"
            )


def _ranges_are_narrower(
    before: LegacyOracleInstallIntervention,
    after: LegacyOracleInstallIntervention,
) -> bool:
    old = tuple(item.output_range for item in before.ranges)
    return all(
        any(previous.offset <= current.offset and current.end <= previous.end for previous in old)
        for current in (item.output_range for item in after.ranges)
    )


@dataclass(frozen=True, slots=True)
class LegacyInterventionEdit:
    """A non-broadening replacement or exact removal of one legacy installation."""

    before: LegacyOracleInstallIntervention
    after: LegacyOracleInstallIntervention | None

    def __post_init__(self) -> None:
        if self.after is None:
            return
        if self.after == self.before:
            raise ClassicAuthorityRepairError(
                f"legacy intervention {self.before.id!r} replacement makes no change"
            )
        unchanged = self.after.model_copy(
            update={
                "allowlist_digest": self.before.allowlist_digest,
                "proof_receipt_digest": self.before.proof_receipt_digest,
                "preimage_digest": self.before.preimage_digest,
                "ranges": self.before.ranges,
                "byte_count": self.before.byte_count,
                "maximum_oracle_payload_bytes": self.before.maximum_oracle_payload_bytes,
            }
        )
        if unchanged != self.before:
            raise ClassicAuthorityRepairError(
                f"legacy intervention {self.before.id!r} replacement changes its identity, "
                "scope, dependency, oracle, or rationale"
            )
        if (
            len(self.after.ranges) > len(self.before.ranges)
            or self.after.byte_count > self.before.byte_count
            or self.after.maximum_oracle_payload_bytes > self.before.maximum_oracle_payload_bytes
            or not _ranges_are_narrower(self.before, self.after)
        ):
            raise ClassicAuthorityRepairError(
                f"legacy intervention {self.before.id!r} replacement broadens its allowlist"
            )


@dataclass(frozen=True, slots=True)
class ClassicDependencyEdit:
    """Move one saved function record onto another donor of its translation unit.

    Everything about the record stays: identity, family, scope, symbol and
    parameters.  Only its primary dependency changes, and the new donor must be
    named so the caller can prove it exists in the same unit.  The receipt's
    donor-side measurements are refreshed separately through the ordinary
    measured-pin repair.
    """

    before: ClassicRecipeIntervention
    donor_id: str
    dropped_parameters: tuple[str, ...] = ()
    """Parameters that described the previous donor pair and go with the move.

    Only the closed set below may be dropped: a debug representation delta
    pairs the record's debug stream with one particular donor's, so it cannot
    survive a move and is re-derived by the measured-pin repair instead.
    """

    def __post_init__(self) -> None:
        if self.before.role is not ClassicRecipeRole.FUNCTION or not self.before.dependencies:
            raise ClassicAuthorityRepairError(
                f"intervention {self.before.id!r} is not a function record with a primary donor"
            )
        if not self.donor_id or self.donor_id == self.before.dependencies[0]:
            raise ClassicAuthorityRepairError(
                f"intervention {self.before.id!r} dependency edit names no new donor"
            )
        names = {field.name for field in self.before.parameters}
        for name in self.dropped_parameters:
            if name not in DROPPABLE_MOVE_PARAMETERS or name not in names:
                raise ClassicAuthorityRepairError(
                    f"intervention {self.before.id!r} dependency edit drops {name!r}, which is "
                    "not a parameter bound to the previous donor"
                )

    @property
    def after(self) -> ClassicRecipeIntervention:
        if self.dropped_parameters:
            return self.before.model_copy(
                update={
                    "dependencies": (self.donor_id, *self.before.dependencies[1:]),
                    "parameters": tuple(
                        field
                        for field in self.before.parameters
                        if field.name not in self.dropped_parameters
                    ),
                }
            )
        return self.before.model_copy(
            update={"dependencies": (self.donor_id, *self.before.dependencies[1:])}
        )


@dataclass(frozen=True, slots=True)
class ClassicReceiptEdit:
    before: ClassicProofReceipt
    after: ClassicProofReceipt | None

    def __post_init__(self) -> None:
        if self.after is None:
            return
        try:
            after = ClassicProofReceipt.model_validate(
                self.after.model_dump(mode="python", warnings=False)
            )
        except ValueError as exc:
            raise ClassicAuthorityRepairError(
                f"receipt {self.before.id!r} replacement is invalid: {exc}"
            ) from exc
        object.__setattr__(self, "after", after)
        if (
            after.id != self.before.id
            or after.intervention_id != self.before.intervention_id
            or after.family is not self.before.family
        ):
            raise ClassicAuthorityRepairError(
                f"receipt {self.before.id!r} replacement changes its identity"
            )
        if after == self.before:
            raise ClassicAuthorityRepairError(f"receipt {self.before.id!r} makes no change")
        unchanged = after.model_copy(update={"expected_values": self.before.expected_values})
        if unchanged != self.before:
            raise ClassicAuthorityRepairError(
                f"receipt {self.before.id!r} replacement changes fields outside expected values"
            )


def _authority_path(root: Path, directory: str, member: str) -> tuple[str, Path]:
    relative = (PurePosixPath(directory) / PurePosixPath(member)).as_posix()
    path = root.joinpath(*PurePosixPath(relative).parts)
    if path.is_symlink() or not path.is_file():
        raise ClassicAuthorityRepairError(f"classic authority is unavailable: {relative!r}")
    return relative, path


def _members(root: Path, directory: str) -> tuple[str, ...]:
    try:
        return json_authority_members(root, directory)
    except AuthoritySnapshotError as exc:
        raise ClassicAuthorityRepairError(
            f"cannot inspect classic authority {directory!r}: {exc}"
        ) from exc


@dataclass(frozen=True, slots=True)
class ClassicRecordAddition:
    """One new function or donor record (intervention plus receipt) for an existing TU shard."""

    intervention: ClassicRecipeIntervention
    receipt: ClassicProofReceipt
    replaces_intervention_id: str | None = None

    def __post_init__(self) -> None:
        if (
            self.receipt.intervention_id != self.intervention.id
            or self.receipt.family is not self.intervention.family
        ):
            raise ClassicAuthorityRepairError(
                f"added receipt {self.receipt.id!r} does not describe {self.intervention.id!r}"
            )
        if self.intervention.role not in (ClassicRecipeRole.FUNCTION, ClassicRecipeRole.DONOR):
            raise ClassicAuthorityRepairError(
                f"added record {self.intervention.id!r} is not a function or donor record"
            )
        if self.intervention.scope.translation_unit is None:
            raise ClassicAuthorityRepairError(
                f"added record {self.intervention.id!r} names no translation-unit shard"
            )
        if self.replaces_intervention_id is not None:
            if not is_identifier(self.replaces_intervention_id):
                raise ClassicAuthorityRepairError("record replacement names an invalid identifier")
            if self.intervention.role is not ClassicRecipeRole.FUNCTION:
                raise ClassicAuthorityRepairError(
                    "only a function record can replace another record"
                )


def _legacy_allowlist_entry(
    intervention: LegacyOracleInstallIntervention,
) -> LegacyAllowlistEntry:
    return LegacyAllowlistEntry(
        intervention_id=intervention.id,
        allowlist_digest=intervention.allowlist_digest,
        proof_receipt_digest=intervention.proof_receipt_digest,
        range_count=len(intervention.ranges),
        byte_count=intervention.byte_count,
        maximum_oracle_payload_bytes=intervention.maximum_oracle_payload_bytes,
    )


_LEGACY_ALLOWLIST_HEADER = re.compile(
    r"(?m)^[ \t]*\[\[[ \t]*authenticity[ \t]*\.[ \t]*legacy_allowlist[ \t]*\]\]"
    r"[ \t]*(?:#[^\r\n]*)?(?:\r\n|\n|\r|$)"
)
_TOML_TABLE_HEADER = re.compile(r"(?m)^[ \t]*\[")
_TOML_DIGEST_VALUE = re.compile(
    r"(?<![A-Za-z0-9_-])value[ \t]*=[ \t]*(?P<quote>['\"])"
    r"(?P<digest>[0-9a-f]{64})(?P=quote)"
)


def _toml_assignment_line(block: str, key: str, intervention_id: str) -> re.Match[str]:
    pattern = re.compile(rf"(?m)^[ \t]*{re.escape(key)}[ \t]*=[^\r\n]*(?:\r\n|\n|\r|$)")
    fields = tuple(pattern.finditer(block))
    if len(fields) != 1:
        raise ClassicAuthorityRepairError(
            f"legacy allowlist entry {intervention_id!r} has {len(fields)} {key!r} fields"
        )
    return fields[0]


def _replace_legacy_digest(
    block: str,
    *,
    intervention_id: str,
    key: str,
    before: str,
    after: str,
) -> str:
    field = _toml_assignment_line(block, key, intervention_id)
    value_source = field.group().split("#", 1)[0]
    values = tuple(_TOML_DIGEST_VALUE.finditer(value_source))
    if len(values) != 1 or values[0].group("digest") != before:
        raise ClassicAuthorityRepairError(
            f"legacy allowlist entry {intervention_id!r} has an unsupported {key!r} value"
        )
    start = field.start() + values[0].start("digest")
    end = field.start() + values[0].end("digest")
    return block[:start] + after + block[end:]


def _replace_legacy_count(
    block: str,
    *,
    intervention_id: str,
    key: str,
    before: int,
    after: int,
) -> str:
    field = _toml_assignment_line(block, key, intervention_id)
    value = re.fullmatch(
        rf"[ \t]*{re.escape(key)}[ \t]*=[ \t]*"
        r"(?P<number>\+?[0-9](?:_?[0-9])*)"
        r"[ \t]*(?:#[^\r\n]*)?(?:\r\n|\n|\r)?",
        field.group(),
    )
    if value is None or int(value.group("number").replace("_", "")) != before:
        raise ClassicAuthorityRepairError(
            f"legacy allowlist entry {intervention_id!r} has an unsupported {key!r} value"
        )
    if before == after:
        return block
    start = field.start() + value.start("number")
    end = field.start() + value.end("number")
    return block[:start] + str(after) + block[end:]


def _remove_legacy_allowlist_block(block: str, intervention_id: str) -> str:
    """Remove one table's semantic lines while retaining surrounding comments."""

    header = _LEGACY_ALLOWLIST_HEADER.match(block)
    if header is None:
        raise ClassicAuthorityRepairError(
            f"legacy allowlist entry {intervention_id!r} has an unsupported table header"
        )
    spans = [(header.start(), header.end())]
    for key in (
        "intervention_id",
        "allowlist_digest",
        "proof_receipt_digest",
        "range_count",
        "byte_count",
        "maximum_oracle_payload_bytes",
    ):
        field = _toml_assignment_line(block, key, intervention_id)
        spans.append((field.start(), field.end()))
    for start, end in sorted(spans, reverse=True):
        block = block[:start] + block[end:]
    return block


def _edit_legacy_allowlist_blocks(
    payload: bytes,
    spec: ProjectSpec,
    edits: tuple[LegacyInterventionEdit, ...],
) -> bytes:
    """Update or remove only exact matching TOML allowlist blocks."""

    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise ClassicAuthorityRepairError("reprobit.toml is not UTF-8") from exc
    try:
        current = ProjectSpec.model_validate_json(canonical_json(tomllib.loads(text)))
    except (tomllib.TOMLDecodeError, ValueError) as exc:
        raise ClassicAuthorityRepairError(f"reprobit.toml is invalid: {exc}") from exc
    if current != spec:
        raise ClassicAuthorityRepairError("reprobit.toml changed before legacy repair")
    headers = tuple(_LEGACY_ALLOWLIST_HEADER.finditer(text))
    if not headers:
        raise ClassicAuthorityRepairError("reprobit.toml has no existing legacy allowlist")
    replacements: list[tuple[int, int, str]] = []
    for edit in edits:
        found: tuple[int, int, str] | None = None
        for match in headers:
            start = match.start()
            following = _TOML_TABLE_HEADER.search(text, match.end())
            end = following.start() if following is not None else len(text)
            block = text[start:end]
            try:
                block_document = tomllib.loads(block)
                identity = block_document["authenticity"]["legacy_allowlist"][0]["intervention_id"]
            except (KeyError, IndexError, TypeError, tomllib.TOMLDecodeError):
                identity = None
            if identity == edit.before.id:
                if found is not None:
                    raise ClassicAuthorityRepairError(
                        f"legacy allowlist repeats {edit.before.id!r}"
                    )
                found = (start, end, block)
        if found is None:
            raise ClassicAuthorityRepairError(
                f"legacy allowlist entry {edit.before.id!r} is absent"
            )
        start, end, block = found
        if edit.after is None:
            replacements.append((start, end, _remove_legacy_allowlist_block(block, edit.before.id)))
            continue
        block = _replace_legacy_digest(
            block,
            intervention_id=edit.before.id,
            key="allowlist_digest",
            before=edit.before.allowlist_digest.value,
            after=edit.after.allowlist_digest.value,
        )
        block = _replace_legacy_digest(
            block,
            intervention_id=edit.before.id,
            key="proof_receipt_digest",
            before=edit.before.proof_receipt_digest.value,
            after=edit.after.proof_receipt_digest.value,
        )
        for key, before_count, after_count in (
            ("range_count", len(edit.before.ranges), len(edit.after.ranges)),
            ("byte_count", edit.before.byte_count, edit.after.byte_count),
            (
                "maximum_oracle_payload_bytes",
                edit.before.maximum_oracle_payload_bytes,
                edit.after.maximum_oracle_payload_bytes,
            ),
        ):
            block = _replace_legacy_count(
                block,
                intervention_id=edit.before.id,
                key=key,
                before=before_count,
                after=after_count,
            )
        replacements.append((start, end, block))
    for start, end, block in sorted(replacements, reverse=True):
        text = text[:start] + block + text[end:]
    try:
        parsed = ProjectSpec.model_validate_json(canonical_json(tomllib.loads(text)))
    except (tomllib.TOMLDecodeError, ValueError) as exc:
        raise ClassicAuthorityRepairError(f"updated reprobit.toml is invalid: {exc}") from exc
    expected_entries = list(spec.authenticity.legacy_allowlist)
    for edit in edits:
        before = _legacy_allowlist_entry(edit.before)
        matches = [index for index, item in enumerate(expected_entries) if item == before]
        if len(matches) != 1:
            raise ClassicAuthorityRepairError(
                f"project legacy allowlist does not exactly match {edit.before.id!r}"
            )
        index = matches[0]
        if edit.after is None:
            del expected_entries[index]
        else:
            expected_entries[index] = _legacy_allowlist_entry(edit.after)
    expected = spec.model_copy(
        update={
            "authenticity": spec.authenticity.model_copy(
                update={"legacy_allowlist": tuple(expected_entries)}
            )
        }
    )
    if parsed != expected:
        raise ClassicAuthorityRepairError("legacy repair changed other reprobit.toml settings")
    return text.encode("utf-8")


def apply_classic_authority_edits(
    root: Path,
    spec: ProjectSpec,
    *,
    interventions: tuple[ClassicInterventionEdit, ...] = (),
    project_overlays: tuple[ClassicProjectOverlayEdit, ...] = (),
    receipts: tuple[ClassicReceiptEdit, ...] = (),
    additions: tuple[ClassicRecordAddition, ...] = (),
    dependencies: tuple[ClassicDependencyEdit, ...] = (),
    legacy_interventions: tuple[LegacyInterventionEdit, ...] = (),
) -> tuple[str, ...]:
    """Apply exact typed edits atomically inside a private staged project.

    ``additions`` add new records to their translation-unit shards, or replace
    a removed function in place when they name it explicitly. Every other
    change is checked against its saved state before it is applied.
    """

    intervention_edits: dict[
        str,
        ClassicInterventionEdit
        | ClassicProjectOverlayEdit
        | ClassicDependencyEdit
        | LegacyInterventionEdit,
    ] = {item.before.id: item for item in interventions}
    for project_edit in project_overlays:
        if project_edit.before.id in intervention_edits:
            raise ClassicAuthorityRepairError("intervention edits repeat an identifier")
        intervention_edits[project_edit.before.id] = project_edit
    for dependency_edit in dependencies:
        if dependency_edit.before.id in intervention_edits:
            raise ClassicAuthorityRepairError("intervention edits repeat an identifier")
        intervention_edits[dependency_edit.before.id] = dependency_edit
    for legacy_edit in legacy_interventions:
        if legacy_edit.before.id in intervention_edits:
            raise ClassicAuthorityRepairError("intervention edits repeat an identifier")
        intervention_edits[legacy_edit.before.id] = legacy_edit
    receipt_edits = {item.before.id: item for item in receipts}
    if len(intervention_edits) != (
        len(interventions) + len(project_overlays) + len(dependencies) + len(legacy_interventions)
    ):
        raise ClassicAuthorityRepairError("intervention edits repeat an identifier")
    if len(receipt_edits) != len(receipts):
        raise ClassicAuthorityRepairError("receipt edits repeat an identifier")
    for legacy_edit in legacy_interventions:
        matching_receipts = [
            item for item in receipts if item.before.intervention_id == legacy_edit.before.id
        ]
        if len(matching_receipts) != 1:
            raise ClassicAuthorityRepairError(
                f"legacy intervention {legacy_edit.before.id!r} needs one matching receipt edit"
            )
        legacy_receipt_edit = matching_receipts[0]
        if (
            Digest.from_bytes(canonical_json(legacy_receipt_edit.before))
            != legacy_edit.before.proof_receipt_digest
        ):
            raise ClassicAuthorityRepairError(
                f"legacy intervention {legacy_edit.before.id!r} receipt differs from its pin"
            )
        if legacy_edit.after is None:
            if legacy_receipt_edit.after is not None:
                raise ClassicAuthorityRepairError(
                    f"removed legacy intervention {legacy_edit.before.id!r} keeps its receipt"
                )
        elif (
            legacy_receipt_edit.after is None
            or Digest.from_bytes(canonical_json(legacy_receipt_edit.after))
            != legacy_edit.after.proof_receipt_digest
        ):
            raise ClassicAuthorityRepairError(
                f"legacy intervention {legacy_edit.before.id!r} replacement receipt differs"
            )
    added_ids = [item.intervention.id for item in additions]
    added_receipt_ids = [item.receipt.id for item in additions]
    if (
        len(set(added_ids)) != len(added_ids)
        or set(added_ids) & set(intervention_edits)
        or len(set(added_receipt_ids)) != len(added_receipt_ids)
        or set(added_receipt_ids) & set(receipt_edits)
    ):
        raise ClassicAuthorityRepairError("record additions repeat an identifier")
    replacements_by_intervention: dict[str, ClassicRecordAddition] = {}
    replacements_by_receipt: dict[str, ClassicRecordAddition] = {}
    for addition in additions:
        replaced_id = addition.replaces_intervention_id
        if replaced_id is None:
            continue
        if replaced_id in replacements_by_intervention:
            raise ClassicAuthorityRepairError(
                f"record replacements repeat intervention {replaced_id!r}"
            )
        intervention_edit = intervention_edits.get(replaced_id)
        if (
            not isinstance(intervention_edit, (ClassicInterventionEdit, LegacyInterventionEdit))
            or intervention_edit.after is not None
        ):
            raise ClassicAuthorityRepairError(
                f"record replacement {addition.intervention.id!r} names no removed function"
            )
        before = intervention_edit.before
        if isinstance(before, LegacyOracleInstallIntervention):
            changed_scope = (
                addition.intervention.scope != before.scope
                or addition.intervention.symbol != before.scope.function
            )
        else:
            changed_scope = (
                before.role is not ClassicRecipeRole.FUNCTION
                or addition.intervention.scope != before.scope
                or addition.intervention.build_target != before.build_target
                or addition.intervention.symbol != before.symbol
            )
        if changed_scope:
            raise ClassicAuthorityRepairError(
                f"record replacement {addition.intervention.id!r} changes the function scope"
            )
        receipt_removals = [
            edit
            for edit in receipts
            if edit.before.intervention_id == replaced_id and edit.after is None
        ]
        if len(receipt_removals) != 1:
            raise ClassicAuthorityRepairError(
                f"record replacement {addition.intervention.id!r} needs one removed receipt"
            )
        replacements_by_intervention[replaced_id] = addition
        replacements_by_receipt[receipt_removals[0].before.id] = addition
    additions_by_shard: dict[tuple[str, str], list[ClassicRecordAddition]] = {}
    for item in additions:
        shard = (item.intervention.scope.target, item.intervention.scope.translation_unit or "")
        additions_by_shard.setdefault(shard, []).append(item)
    if not intervention_edits and not receipt_edits and not additions:
        return ()
    placed_interventions: set[str] = set()
    placed_receipts: set[str] = set()
    donors_by_shard: dict[tuple[str, str], set[str]] = {}

    transaction = CASTransaction(root)
    changed_paths: list[str] = []
    found_interventions: set[str] = set()
    found_receipts: set[str] = set()
    intervention_members = _members(root, spec.layout.interventions)
    proof_members = _members(root, spec.layout.proofs)

    for member in intervention_members:
        relative, path = _authority_path(root, spec.layout.interventions, member)
        payload = path.read_bytes()
        try:
            intervention_document = InterventionDocument.model_validate_json(payload)
        except ValueError as exc:
            raise ClassicAuthorityRepairError(
                f"invalid intervention authority {relative!r}: {exc}"
            ) from exc
        intervention_values = list(intervention_document.interventions)
        changed = False
        for index in range(len(intervention_values) - 1, -1, -1):
            current = intervention_values[index]
            intervention_edit = intervention_edits.get(current.id)
            if intervention_edit is None:
                continue
            expected_type = (
                LegacyOracleInstallIntervention
                if isinstance(intervention_edit, LegacyInterventionEdit)
                else ClassicRecipeIntervention
            )
            if not isinstance(current, expected_type) or current != intervention_edit.before:
                raise ClassicAuthorityRepairError(
                    f"intervention {current.id!r} changed before repair was applied"
                )
            if current.id in found_interventions:
                raise ClassicAuthorityRepairError(
                    f"intervention {current.id!r} appears more than once"
                )
            found_interventions.add(current.id)
            if intervention_edit.after is None:
                record_replacement = replacements_by_intervention.get(current.id)
                if record_replacement is None:
                    del intervention_values[index]
                else:
                    if record_replacement.intervention.id in placed_interventions:
                        raise ClassicAuthorityRepairError(
                            f"record replacement {record_replacement.intervention.id!r} was placed "
                            "more than once"
                        )
                    if any(
                        item.id == record_replacement.intervention.id
                        for position, item in enumerate(intervention_values)
                        if position != index
                    ):
                        raise ClassicAuthorityRepairError(
                            "added record "
                            f"{record_replacement.intervention.id!r} already exists in "
                            f"{relative!r}"
                        )
                    if (
                        isinstance(current, LegacyOracleInstallIntervention)
                        and record_replacement.intervention.build_target
                        != intervention_document.build_target
                    ):
                        raise ClassicAuthorityRepairError(
                            f"record replacement {record_replacement.intervention.id!r} changes "
                            "the legacy action's build target"
                        )
                    intervention_values[index] = record_replacement.intervention
                    placed_interventions.add(record_replacement.intervention.id)
            else:
                intervention_values[index] = intervention_edit.after
            changed = True
        shard = (intervention_document.target_id, intervention_document.translation_unit_id or "")
        donors_by_shard[shard] = {
            item.id
            for item in intervention_values
            if isinstance(item, ClassicRecipeIntervention) and item.role is ClassicRecipeRole.DONOR
        } | {
            item.intervention.id
            for item in additions_by_shard.get(shard, ())
            if item.intervention.role is ClassicRecipeRole.DONOR
        }
        for dependency_edit in dependencies:
            if (
                dependency_edit.before.scope.target == shard[0]
                and dependency_edit.before.scope.translation_unit == shard[1]
                and dependency_edit.donor_id not in donors_by_shard[shard]
            ):
                raise ClassicAuthorityRepairError(
                    f"dependency edit for {dependency_edit.before.id!r} names donor "
                    f"{dependency_edit.donor_id!r} outside its translation unit"
                )
        shard_additions = (
            additions_by_shard.get(shard, ()) if intervention_document.translation_unit_id else ()
        )
        for addition in shard_additions:
            if addition.replaces_intervention_id is not None:
                continue
            if addition.intervention.id in placed_interventions:
                raise ClassicAuthorityRepairError(
                    f"added record {addition.intervention.id!r} matches more than one "
                    "intervention document"
                )
            if any(item.id == addition.intervention.id for item in intervention_values):
                raise ClassicAuthorityRepairError(
                    f"added record {addition.intervention.id!r} already exists in {relative!r}"
                )
            intervention_values.append(addition.intervention)
            placed_interventions.add(addition.intervention.id)
            changed = True
        digest = Digest.from_bytes(payload).value
        if not changed:
            transaction.assert_unchanged(relative, expected_sha256=digest)
            continue
        intervention_candidate = InterventionDocument.model_validate(
            {
                **intervention_document.model_dump(mode="python"),
                "interventions": tuple(intervention_values),
            }
        )
        transaction.write(
            relative,
            canonical_json(intervention_candidate),
            expected_sha256=digest,
        )
        changed_paths.append(relative)

    for member in proof_members:
        relative, path = _authority_path(root, spec.layout.proofs, member)
        payload = path.read_bytes()
        try:
            proof_document = ProofDocument.model_validate_json(payload)
        except ValueError as exc:
            raise ClassicAuthorityRepairError(
                f"invalid proof authority {relative!r}: {exc}"
            ) from exc
        receipt_values = list(proof_document.expected_observations)
        changed = False
        for index in range(len(receipt_values) - 1, -1, -1):
            receipt_current = receipt_values[index]
            receipt_edit = receipt_edits.get(receipt_current.id)
            if receipt_edit is None:
                continue
            if receipt_current != receipt_edit.before:
                raise ClassicAuthorityRepairError(
                    f"proof receipt {receipt_current.id!r} changed before repair was applied"
                )
            if receipt_current.id in found_receipts:
                raise ClassicAuthorityRepairError(
                    f"proof receipt {receipt_current.id!r} appears more than once"
                )
            found_receipts.add(receipt_current.id)
            if receipt_edit.after is None:
                record_replacement = replacements_by_receipt.get(receipt_current.id)
                if record_replacement is None:
                    del receipt_values[index]
                else:
                    if record_replacement.receipt.id in placed_receipts:
                        raise ClassicAuthorityRepairError(
                            "record replacement receipt "
                            f"{record_replacement.receipt.id!r} was placed "
                            "more than once"
                        )
                    if any(
                        item.id == record_replacement.receipt.id
                        for position, item in enumerate(receipt_values)
                        if position != index
                    ):
                        raise ClassicAuthorityRepairError(
                            f"added receipt {record_replacement.receipt.id!r} already exists in "
                            f"{relative!r}"
                        )
                    receipt_values[index] = record_replacement.receipt
                    placed_receipts.add(record_replacement.receipt.id)
            else:
                receipt_values[index] = receipt_edit.after
            changed = True
        shard = (proof_document.target_id, proof_document.translation_unit_id or "")
        shard_additions = (
            additions_by_shard.get(shard, ()) if proof_document.translation_unit_id else ()
        )
        for addition in shard_additions:
            if addition.replaces_intervention_id is not None:
                continue
            if addition.receipt.id in placed_receipts:
                raise ClassicAuthorityRepairError(
                    f"added receipt {addition.receipt.id!r} matches more than one proof document"
                )
            if any(item.id == addition.receipt.id for item in receipt_values):
                raise ClassicAuthorityRepairError(
                    f"added receipt {addition.receipt.id!r} already exists in {relative!r}"
                )
            receipt_values.append(addition.receipt)
            placed_receipts.add(addition.receipt.id)
            changed = True
        digest = Digest.from_bytes(payload).value
        if not changed:
            transaction.assert_unchanged(relative, expected_sha256=digest)
            continue
        proof_candidate = ProofDocument.model_validate(
            {
                **proof_document.model_dump(mode="python"),
                "expected_observations": tuple(receipt_values),
            }
        )
        transaction.write(relative, canonical_json(proof_candidate), expected_sha256=digest)
        changed_paths.append(relative)

    unplaced_interventions = sorted(set(added_ids) - placed_interventions, key=str.casefold)
    unplaced_receipts = sorted(set(added_receipt_ids) - placed_receipts, key=str.casefold)
    if unplaced_interventions or unplaced_receipts:
        raise ClassicAuthorityRepairError(
            "record additions name translation-unit shards without documents: "
            f"interventions={unplaced_interventions}, receipts={unplaced_receipts}"
        )
    missing_interventions = sorted(
        set(intervention_edits) - found_interventions,
        key=str.casefold,
    )
    missing_receipts = sorted(set(receipt_edits) - found_receipts, key=str.casefold)
    if missing_interventions or missing_receipts:
        raise ClassicAuthorityRepairError(
            "classic authority edits are absent: "
            f"interventions={missing_interventions}, receipts={missing_receipts}"
        )
    if legacy_interventions:
        relative = "reprobit.toml"
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ClassicAuthorityRepairError("reprobit.toml is unavailable")
        payload = path.read_bytes()
        replacement = _edit_legacy_allowlist_blocks(payload, spec, legacy_interventions)
        if replacement == payload:
            raise ClassicAuthorityRepairError("legacy allowlist replacement makes no change")
        transaction.write(
            relative,
            replacement,
            expected_sha256=Digest.from_bytes(payload).value,
        )
        changed_paths.append(relative)
    transaction.assert_json_members(
        spec.layout.interventions,
        expected_members=intervention_members,
    )
    transaction.assert_json_members(spec.layout.proofs, expected_members=proof_members)
    transaction.commit()
    return tuple(sorted(changed_paths, key=lambda item: (item.casefold(), item)))


__all__ = [
    "DROPPABLE_MOVE_PARAMETERS",
    "ClassicAuthorityRepairError",
    "ClassicDependencyEdit",
    "ClassicInterventionEdit",
    "ClassicProjectOverlayEdit",
    "ClassicReceiptEdit",
    "ClassicRecordAddition",
    "LegacyInterventionEdit",
    "apply_classic_authority_edits",
]
