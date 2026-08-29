"""One-way conversion of a schema-v2 monolith into strict schema-v3 shards."""

from __future__ import annotations

import hashlib
import json
import ntpath
import os
import re
import shlex
import stat
import tempfile
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path, PurePosixPath
from typing import Any, Literal, cast

from pydantic import ValidationError

from reprobit.model import AuthenticityPolicy, ByteRange, Digest, Scope
from reprobit.paths import normalize_logical_path
from reprobit.project_loader import load_project_tree
from reprobit.schema import (
    BuildPlanDocument,
    ClassicArchiveAuthority,
    ClassicField,
    ClassicGroupOrderPlan,
    ClassicProofReceipt,
    ClassicProofRedaction,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    ClassicSdkArchiveAuthority,
    ClassicTargetGate,
    ClassicTranslationUnitPlan,
    Intervention,
    InterventionDocument,
    LegacyAllowlistEntry,
    LegacyOracleInstallIntervention,
    LockedTool,
    MsvcRelease,
    OracleDocument,
    OracleInstallRange,
    ProjectBundle,
    ProofDocument,
    SourceManifestDocument,
    SourceManifestEntry,
    ToolchainLock,
    ToolchainProfileSource,
    source_manifest_digest,
)
from reprobit.strict_json import JsonValue, StrictJSONError, canonical_json, strict_load
from reprobit.toolchains import (
    MSVC_42,
    TOOLCHAIN_PROFILES,
    profile_source_pins_for_paths,
)


class MigrationError(ValueError):
    """Raised when a legacy manifest cannot be converted without guessing."""


@dataclass(frozen=True)
class MigrationOutput:
    """A deterministic set of project-relative migration outputs."""

    files: dict[PurePosixPath, bytes]
    source_sha256: str
    intervention_count: int
    proof_count: int


def validate_migration_files(
    files: Mapping[PurePosixPath, bytes],
) -> ProjectBundle:
    """Load and cross-validate one complete in-memory migration candidate."""

    with tempfile.TemporaryDirectory(prefix="reprobit-migration-") as directory:
        root = Path(directory)
        for relative, data in files.items():
            destination = root.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        return load_project_tree(root, verify_source_authority=False)


_SAFE_ID = re.compile(r"[^a-z0-9_.-]+")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_PREFIXES = (
    "expected_",
    "retail_",
    "accepted_",
    "required_row_",
    "row_identity_",
    "rendered_sha",
    "clean_sha",
)
_FORBIDDEN_RECIPE_MARKERS = (
    "bytes",
    "payload",
    "oracle_path",
    "reference_path",
    "callable",
    "script",
    "python",
    "template",
)
_SAFE_PAYLOAD_EVIDENCE_NAMES = frozenset(
    {
        "expected_linker_payload_count",
        "expected_linker_payload_sha256",
    }
)
_HOST_ABSOLUTE_ROOTS = (
    "/Applications/",
    "/Library/",
    "/System/",
    "/Users/",
    "/Volumes/",
    "/bin/",
    "/home/",
    "/opt/",
    "/private/",
    "/sbin/",
    "/tmp/",
    "/usr/",
    "/var/",
)
_FUNCTION_CLAIM_GENERATORS = frozenset(
    {"assert_reseat", "empty_scopes", "literal_alias", "local_ids", "noop_assign"}
)


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise MigrationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def load_legacy_manifest(path: Path) -> tuple[dict[str, Any], str]:
    """Load the sole legacy input format; normal runtime remains v3-only."""

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise MigrationError(f"cannot read migration input: {exc}") from exc

    def reject_constant(value: str) -> None:
        raise MigrationError(f"non-finite JSON number: {value}")

    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MigrationError(f"invalid JSON: {exc}") from exc
    if not isinstance(parsed, dict) or parsed.get("schema") != 2:
        raise MigrationError("migration input must be a schema-v2 object")
    return parsed, hashlib.sha256(raw).hexdigest()


def _load_semantic_claims_sidecar(path: Path | None) -> dict[str, Any] | None:
    """Load the reviewed, one-shot source-overlay migration claims."""

    if path is None:
        return None
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise MigrationError(f"cannot read semantic-claims sidecar: {exc}") from exc

    def reject_constant(value: str) -> None:
        raise MigrationError(f"non-finite JSON number in semantic-claims sidecar: {value}")

    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MigrationError(f"invalid semantic-claims sidecar JSON: {exc}") from exc
    if (
        not isinstance(parsed, dict)
        or set(parsed) != {"bindings", "schema"}
        or type(parsed.get("schema")) is not int
        or parsed.get("schema") != 1
        or not isinstance(parsed.get("bindings"), list)
    ):
        raise MigrationError(
            "semantic-claims sidecar must be exactly a schema-1 {schema, bindings} object"
        )
    return parsed


def _canonical(value: Any) -> bytes:
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return (rendered + "\n").encode()


def _model_bytes(value: Any) -> bytes:
    return canonical_json(value)


def _stable_id(prefix: str, value: Any) -> str:
    digest = hashlib.sha256(_canonical(value)).hexdigest()[:16]
    return f"{prefix}_{digest}"


def _slug(value: str) -> str:
    slug = _SAFE_ID.sub("-", value.casefold()).strip("-.")
    if not slug:
        raise MigrationError(f"cannot derive stable ID from {value!r}")
    return slug[:128]


def _digest(value: Any, context: str) -> Digest:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise MigrationError(f"{context} is not lowercase SHA-256")
    return Digest(value=value)


def _relative(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise MigrationError(f"{context} must be a non-empty relative path")
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        raise MigrationError(f"{context} must be project-relative")
    parts = PurePosixPath(normalized).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise MigrationError(f"{context} must be normalized and project-relative")
    return PurePosixPath(*parts).as_posix()


def _declared_source_pins(manifest: Mapping[str, Any]) -> dict[str, tuple[Digest, int | None]]:
    """Collect finite v2 file pins without treating them as a complete read set."""

    pins: dict[str, tuple[str, Digest, int | None]] = {}

    def add(path_value: Any, digest_value: Any, size_value: Any, context: str) -> None:
        path = _relative(path_value, context)
        digest = _digest(digest_value, f"{context} digest")
        size = size_value if type(size_value) is int and size_value >= 0 else None
        key = path.casefold()
        previous = pins.get(key)
        if previous is not None and previous[1] != digest:
            raise MigrationError(f"{context} conflicts with another pin for {path!r}")
        pins[key] = (path, digest, size)

    units = manifest.get("translation_units")
    if isinstance(units, list):
        for index, unit in enumerate(units):
            if isinstance(unit, dict):
                add(
                    unit.get("source"),
                    unit.get("source_sha256"),
                    unit.get("source_size"),
                    f"translation unit {index} source",
                )
    archives = manifest.get("archives")
    if isinstance(archives, list):
        for index, archive in enumerate(archives):
            if isinstance(archive, dict):
                add(
                    archive.get("source"),
                    archive.get("source_sha256"),
                    archive.get("source_size"),
                    f"archive {index} source",
                )
    terminal = manifest.get("terminal_producers")
    link = terminal.get("link") if isinstance(terminal, dict) else None
    libraries = link.get("project_sdk_libraries") if isinstance(link, dict) else None
    if isinstance(libraries, list):
        for index, library in enumerate(libraries):
            if isinstance(library, dict):
                add(
                    library.get("path"),
                    library.get("sha256"),
                    library.get("size"),
                    f"project SDK library {index}",
                )

    # Overlay clean pins are the base-tree authority. TU pins for these paths
    # describe the rendered result and are intentionally replaced.
    overlay = manifest.get("source_overlay")
    outputs = overlay.get("outputs") if isinstance(overlay, dict) else None
    if isinstance(outputs, list):
        for index, output in enumerate(outputs):
            if not isinstance(output, dict):
                continue
            path = _relative(output.get("path"), f"source overlay {index} path")
            digest = _digest(
                output.get("clean", hashlib.sha256(b"").hexdigest()),
                f"source overlay {path} clean digest",
            )
            size_value = output.get("clean_size")
            size = size_value if type(size_value) is int and size_value >= 0 else None
            pins[path.casefold()] = (path, digest, size)
    return {path: (digest, size) for path, digest, size in pins.values()}


def _source_manifest(
    manifest: Mapping[str, Any], *, source_root: Path | None
) -> SourceManifestDocument:
    empty_digest = hashlib.sha256(b"").hexdigest()
    declared = _declared_source_pins(manifest)
    if source_root is not None:
        from reprobit.source_lock import build_source_manifest, git_tracked_paths

        tracked = set(git_tracked_paths(source_root))
        tracked.update(
            relative
            for relative, (digest, _) in declared.items()
            if source_root.joinpath(*PurePosixPath(relative).parts).is_file()
            or digest.value != empty_digest
        )
        images = manifest.get("images")
        forbidden: set[str] = set()
        if isinstance(images, dict):
            for image in images.values():
                if not isinstance(image, dict):
                    continue
                for key in ("original", "recompiled"):
                    value = image.get(key)
                    if isinstance(value, str):
                        forbidden.add(_relative(value, f"image {key}").casefold())
        tracked = {item for item in tracked if item.casefold() not in forbidden}
        document = build_source_manifest(source_root, tracked, complete=True)
        actual = {item.path.casefold(): item for item in document.entries}
        for relative, (declared_digest, declared_size) in declared.items():
            entry = actual.get(relative.casefold())
            if entry is None and declared_digest.value == empty_digest:
                continue
            if entry is None or entry.digest != declared_digest:
                received = None if entry is None else entry.digest.value
                raise MigrationError(
                    f"declared source input digest differs for {relative!r}: {received}"
                )
            if declared_size is not None and declared_size != entry.size:
                raise MigrationError(f"declared source input size differs for {relative!r}")
        return document

    entries: list[SourceManifestEntry] = []
    for relative, (declared_digest, declared_size) in declared.items():
        if source_root is None:
            if declared_size is None:
                raise MigrationError(
                    f"source size for {relative!r} is absent; supply the physical project root"
                )
            size = declared_size
        entries.append(SourceManifestEntry(path=relative, size=size, digest=declared_digest))
    if not entries:
        raise MigrationError("legacy manifest declares no portable source inputs")
    return SourceManifestDocument(
        schema_version=3,
        complete=True,
        entries=tuple(sorted(entries, key=lambda item: (item.path.casefold(), item.path))),
    )


def _json_value(value: Any, context: str = "legacy value") -> JsonValue:
    if isinstance(value, str) and value.startswith(_HOST_ABSOLUTE_ROOTS):
        return cast(JsonValue, "Z:" + value.replace("/", "\\"))
    if value is None or type(value) in {bool, int, float, str}:
        return cast(JsonValue, value)
    if isinstance(value, list):
        return [_json_value(item, f"{context}[]") for item in value]
    if isinstance(value, dict):
        result: dict[str, JsonValue] = {}
        for key in sorted(value):
            if not isinstance(key, str):
                raise MigrationError(f"{context} contains a non-string key")
            result[key] = _json_value(value[key], f"{context}.{key}")
        return result
    raise MigrationError(f"{context} has unsupported type {type(value).__name__}")


def _is_evidence_name(name: str) -> bool:
    return name.startswith(_EVIDENCE_PREFIXES)


def _is_forbidden_recipe_name(name: str) -> bool:
    normalized = name.casefold()
    # These are scalar proof metadata about a freshly produced link-directive
    # multiset, not payload bytes.  Self-permutation validation needs them to
    # reject a seed/donor pair whose otherwise-identical object closure carries
    # different linker semantics.
    if normalized in _SAFE_PAYLOAD_EVIDENCE_NAMES:
        return False
    return any(marker in normalized for marker in _FORBIDDEN_RECIPE_MARKERS)


@dataclass
class _ProofPins:
    expected_values: dict[str, JsonValue]
    redactions: dict[str, Digest]


def _record_expected(pins: _ProofPins, path: str, value: Any) -> None:
    if path in pins.expected_values or path in pins.redactions:
        raise MigrationError(f"duplicate proof pin path: {path}")
    pins.expected_values[path] = _json_value(value, path)


def _record_redaction(pins: _ProofPins, path: str, value: Any) -> None:
    if path in pins.expected_values or path in pins.redactions:
        raise MigrationError(f"duplicate proof pin path: {path}")
    pins.redactions[path] = Digest.from_bytes(_canonical(value))


def _proof_receipt(
    *,
    receipt_id: str,
    intervention_id: str,
    family: ClassicRecipeFamily,
    pins: _ProofPins,
    status: str | None = None,
    authenticity: str | None = None,
) -> ClassicProofReceipt:
    return ClassicProofReceipt(
        id=receipt_id,
        intervention_id=intervention_id,
        family=family,
        expected_values={key: pins.expected_values[key] for key in sorted(pins.expected_values)},
        redactions=tuple(
            ClassicProofRedaction(source_path=path, evidence_digest=pins.redactions[path])
            for path in sorted(pins.redactions)
        ),
        status=status,
        authenticity=authenticity,
    )


def _safe_recipe_value(
    value: Any,
    path: str,
    pins: _ProofPins,
) -> JsonValue:
    if isinstance(value, dict):
        result: dict[str, JsonValue] = {}
        for key in sorted(value):
            if not isinstance(key, str):
                raise MigrationError(f"{path} contains a non-string key")
            child_path = f"{path}.{key}"
            child = value[key]
            if _is_forbidden_recipe_name(key):
                _record_redaction(pins, child_path, child)
            elif _is_evidence_name(key):
                _record_expected(pins, child_path, child)
            else:
                result[key] = _safe_recipe_value(child, child_path, pins)
        return result
    if isinstance(value, list):
        return [
            _safe_recipe_value(item, f"{path}[{index}]", pins) for index, item in enumerate(value)
        ]
    return _json_value(value, path)


def _recipe_fields(
    values: Mapping[str, Any],
    pins: _ProofPins,
    prefix: str,
) -> tuple[ClassicField, ...]:
    fields: list[ClassicField] = []
    for key in sorted(values):
        path = f"{prefix}.{key}" if prefix else key
        value = values[key]
        if _is_forbidden_recipe_name(key):
            _record_redaction(pins, path, value)
        elif _is_evidence_name(key):
            _record_expected(pins, path, value)
        else:
            fields.append(
                ClassicField(
                    name=key,
                    value=_safe_recipe_value(value, path, pins),
                )
            )
    return tuple(fields)


def _migrate_donor_compile_lane(
    values: dict[str, Any],
    family: ClassicRecipeFamily,
    *,
    context: str,
) -> str | None:
    """Consume the v2 lane marker and return its one-shot define selector.

    The runtime has one current donor schema and never interprets the old
    selector.  This converter uses it only to recover current build-target
    authority from the legacy compile database, while promoting the independently
    meaningful include projection used by source-overlay donors.
    """

    raw = values.pop("compile_lane", None)
    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) - {"required_define", "include_projection"}:
        raise MigrationError(f"{context} compile_lane has an unsupported legacy shape")
    required_define = raw.get("required_define")
    if not isinstance(required_define, str) or not required_define:
        raise MigrationError(f"{context} compile_lane lacks its historical required_define")
    projection = raw.get("include_projection")
    if projection is None:
        return required_define
    if family is not ClassicRecipeFamily.DONOR_SOURCE_OVERLAY:
        raise MigrationError(f"{context} attaches include_projection to a non-overlay donor")
    existing = values.get("include_projection")
    if existing is not None and existing != projection:
        raise MigrationError(f"{context} has conflicting include_projection authority")
    values["include_projection"] = projection
    return required_define


def _legacy_workspace_root(contract: Mapping[str, Any]) -> PurePosixPath:
    value = contract.get("build_root")
    if not isinstance(value, str):
        raise MigrationError("legacy path contract lacks its build root")
    workspace = PurePosixPath(value)
    if (
        not workspace.is_absolute()
        or workspace.as_posix() != value
        or any(part in {"", ".", ".."} for part in workspace.parts[1:])
    ):
        raise MigrationError("legacy path contract build root is not canonical")
    return workspace


def _compile_record_path(value: str, *, directory: Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = directory / path
    return path.resolve(strict=False)


def _cmake_compile_owner(output: Path, *, build_root: Path, context: str) -> str:
    try:
        relative = output.relative_to(build_root)
    except ValueError as exc:
        raise MigrationError(f"{context} object output escapes the legacy CMake build") from exc
    parts = relative.parts
    matches = [
        parts[index + 1][:-4]
        for index in range(len(parts) - 1)
        if parts[index].casefold() == "cmakefiles"
        and parts[index + 1].casefold().endswith(".dir")
        and len(parts[index + 1]) > 4
    ]
    if len(matches) != 1:
        raise MigrationError(f"{context} object output has no unique CMake target owner")
    return matches[0]


def _legacy_compile_lane_owners(
    manifest: Mapping[str, Any],
) -> dict[tuple[str, str], tuple[str, ...]]:
    """Index the compile lanes that the schema-v2 runner selected by define."""

    toolchain = manifest.get("toolchain")
    contract = toolchain.get("codegen_path_contract") if isinstance(toolchain, dict) else None
    if not isinstance(contract, dict):
        raise MigrationError("legacy toolchain lacks compiler-visible path contract")
    workspace = _legacy_workspace_root(contract)
    workspace_path = Path(workspace.as_posix()).resolve(strict=False)
    build_root = (workspace_path / "build").resolve(strict=False)
    source_root = (workspace_path / "src").resolve(strict=False)
    database_path = build_root / "compile_commands.json"
    try:
        raw_database = strict_load(database_path)
    except StrictJSONError as exc:
        raise MigrationError(f"cannot load legacy compile database {database_path}: {exc}") from exc
    if not isinstance(raw_database, list):
        raise MigrationError("legacy compile_commands.json must be an array")

    owners: defaultdict[tuple[str, str], list[str]] = defaultdict(list)
    for index, raw_record in enumerate(raw_database):
        context = f"legacy compile record {index}"
        if not isinstance(raw_record, dict):
            raise MigrationError(f"{context} is not an object")
        raw_directory = raw_record.get("directory")
        raw_source = raw_record.get("file")
        command = raw_record.get("command")
        record_values = (raw_directory, raw_source, command)
        if not all(isinstance(value, str) and value for value in record_values):
            raise MigrationError(f"{context} lacks directory, file, or command")
        assert isinstance(raw_directory, str)
        assert isinstance(raw_source, str)
        assert isinstance(command, str)
        directory = _compile_record_path(raw_directory, directory=build_root)
        if directory != build_root:
            raise MigrationError(f"{context} uses an unexpected working directory")
        source_path = _compile_record_path(raw_source, directory=directory)
        try:
            logical_source = source_path.relative_to(source_root).as_posix()
        except ValueError as exc:
            raise MigrationError(f"{context} source escapes the legacy staged source root") from exc
        try:
            arguments = tuple(shlex.split(command))
        except ValueError as exc:
            raise MigrationError(f"{context} command cannot be parsed: {exc}") from exc
        output_value = raw_record.get("output")
        if not isinstance(output_value, str) or not output_value:
            output_value = next(
                (
                    argument[3:]
                    for argument in arguments
                    if argument.casefold().startswith(("/fo", "-fo"))
                    and len(argument) > 3
                ),
                None,
            )
        if output_value is None:
            raise MigrationError(f"{context} lacks its object output")
        output = _compile_record_path(output_value, directory=directory)
        owner = _cmake_compile_owner(
            output,
            build_root=build_root,
            context=context,
        )
        defines = {
            argument[2:]
            for argument in arguments
            if argument.startswith("-D") and len(argument) > 2
        }
        for required_define in defines:
            owners[(logical_source, required_define)].append(owner)
    return {key: tuple(value) for key, value in owners.items()}


def _legacy_compile_lane_owner(
    owners: Mapping[tuple[str, str], tuple[str, ...]],
    *,
    source: str,
    required_define: str,
    context: str,
) -> str:
    matches = owners.get((source, required_define), ())
    if len(matches) != 1:
        raise MigrationError(
            f"{context} expected one legacy compile command for "
            f"{source!r} with -D{required_define}, found {len(matches)}"
        )
    return matches[0]


def _migrate_donor_references(
    values: dict[str, Any],
    donor_ids: Mapping[str, str],
    *,
    context: str,
) -> None:
    """Replace every v2 donor selector with its current intervention ID."""

    for name in ("target_donor", "complete_donor", "instruction_donor"):
        legacy_id = values.get(name)
        if legacy_id is None:
            continue
        if not isinstance(legacy_id, str) or legacy_id not in donor_ids:
            raise MigrationError(f"{context} names unknown {name} {legacy_id!r}")
        values[name] = donor_ids[legacy_id]

    ranges = values.get("instruction_ranges")
    if ranges is not None:
        if not isinstance(ranges, list):
            raise MigrationError(f"{context} instruction_ranges is not an array")
        migrated_ranges: list[dict[str, Any]] = []
        for index, raw in enumerate(ranges):
            if not isinstance(raw, dict):
                raise MigrationError(f"{context} instruction_ranges[{index}] is not an object")
            legacy_id = raw.get("donor")
            if legacy_id is None:
                migrated_ranges.append(raw)
                continue
            if not isinstance(legacy_id, str) or legacy_id not in donor_ids:
                raise MigrationError(
                    f"{context} instruction_ranges[{index}] names unknown donor "
                    f"{legacy_id!r}"
                )
            migrated_ranges.append({**raw, "donor": donor_ids[legacy_id]})
        values["instruction_ranges"] = migrated_ranges

    variants = values.get("donor_variants")
    if variants is None:
        return
    if not isinstance(variants, list):
        raise MigrationError(f"{context} donor_variants is not an array")
    migrated: list[dict[str, Any]] = []
    for index, raw in enumerate(variants):
        if not isinstance(raw, dict):
            raise MigrationError(f"{context} donor_variants[{index}] is not an object")
        legacy_id = raw.get("donor")
        if not isinstance(legacy_id, str) or legacy_id not in donor_ids:
            raise MigrationError(
                f"{context} donor_variants[{index}] names unknown donor {legacy_id!r}"
            )
        migrated.append({**raw, "donor": donor_ids[legacy_id]})
    values["donor_variants"] = migrated


def _family(value: Any, context: str) -> ClassicRecipeFamily:
    if not isinstance(value, str):
        raise MigrationError(f"{context} recipe family is missing")
    try:
        return ClassicRecipeFamily(value)
    except ValueError as exc:
        raise MigrationError(f"{context} has unsupported recipe family {value!r}") from exc


def _final_target(
    build_target: str,
    source: str,
    target_by_build: Mapping[str, str],
) -> str:
    normalized_target = _slug(build_target)
    if normalized_target in target_by_build:
        return target_by_build[normalized_target]
    first_source_part = _slug(PurePosixPath(source.replace("\\", "/")).parts[0])
    final_targets = set(target_by_build.values())
    if first_source_part in final_targets:
        return first_source_part
    if len(final_targets) == 1:
        return next(iter(final_targets))
    raise MigrationError(
        f"cannot associate build target {build_target!r} / source {source!r} with a final image"
    )


def _target_declarations(
    images: Any,
) -> tuple[list[dict[str, Any]], dict[str, str], dict[str, str]]:
    if not isinstance(images, dict) or not images:
        raise MigrationError("legacy images must be a non-empty object")
    targets: list[dict[str, Any]] = []
    by_build: dict[str, str] = {}
    aliases: dict[str, str] = {}
    for image_id, image in sorted(images.items()):
        if not isinstance(image_id, str) or not isinstance(image, dict):
            raise MigrationError("invalid image declaration")
        target_id = _slug(image_id)
        raw_build_target = image.get("target")
        if not isinstance(raw_build_target, str):
            raise MigrationError(f"image {image_id!r} lacks build target")
        build_target = _slug(raw_build_target)
        if build_target in by_build and by_build[build_target] != target_id:
            raise MigrationError(f"two images use build target {build_target!r}")
        by_build[build_target] = target_id
        artifact = _relative(image.get("recompiled"), f"image {image_id} output")
        if "/" not in artifact:
            artifact = f"build/{artifact}"
        oracle = _relative(image.get("original"), f"image {image_id} oracle")
        target = {
            "id": target_id,
            "build_target": build_target,
            "artifact": artifact,
            "oracle": oracle,
            "image": image,
        }
        targets.append(target)
        for alias in (
            image_id,
            build_target,
            Path(artifact).name,
            Path(artifact).stem,
            Path(oracle).name,
            Path(oracle).stem,
        ):
            aliases[_slug(alias)] = target_id
    return targets, by_build, aliases


def _legacy_install(
    *,
    intervention_id: str,
    target_id: str,
    tu_id: str,
    symbol: str,
    function: Mapping[str, Any],
    dependency: str | None,
    aliases: Mapping[str, str],
    proof_receipt: ClassicProofReceipt,
) -> LegacyOracleInstallIntervention:
    spec = function.get("simulated_elision")
    oracle = function.get("retail_oracle")
    if not isinstance(spec, dict) or not isinstance(oracle, dict):
        raise MigrationError(f"legacy oracle action {symbol!r} lacks ranges/oracle")
    regions = spec.get("regions")
    if not isinstance(regions, list) or not regions:
        raise MigrationError(f"legacy oracle action {symbol!r} has no declared regions")
    ranges: list[OracleInstallRange] = []
    previous_preimage_end = 0
    for index, region in enumerate(regions):
        if not isinstance(region, dict):
            raise MigrationError(f"legacy oracle action {symbol!r} region {index} is invalid")
        values = tuple(
            region.get(key) for key in ("region_start", "region_end", "image_start", "image_length")
        )
        if not all(type(value) is int for value in values):
            raise MigrationError(f"legacy oracle action {symbol!r} region {index} is incomplete")
        start, end, image_start, image_length = cast(tuple[int, int, int, int], values)
        if (
            start < previous_preimage_end
            or start < 0
            or end <= start
            or image_start < 0
            or image_length < 1
        ):
            raise MigrationError(f"legacy oracle action {symbol!r} region {index} is invalid")
        previous_preimage_end = end
        ranges.append(
            OracleInstallRange(
                preimage_range=ByteRange(offset=start, length=end - start),
                output_range=ByteRange(offset=image_start, length=image_length),
                oracle_range=ByteRange(offset=image_start, length=image_length),
            )
        )
    ordered = sorted(ranges, key=lambda item: item.output_range.offset)
    if any(left.output_range.overlaps(right.output_range) for left, right in pairwise(ordered)):
        raise MigrationError(f"legacy oracle action {symbol!r} has overlapping output ranges")
    oracle_length = oracle.get("length")
    if type(oracle_length) is not int or any(
        item.oracle_range.end > oracle_length for item in ranges
    ):
        raise MigrationError(f"legacy oracle action {symbol!r} leaves its oracle body")
    maximum_oracle_payload_bytes = oracle_length
    for key in ("callee_oracles", "vtable_oracles"):
        raw_auxiliary = spec.get(key, [])
        if not isinstance(raw_auxiliary, list):
            raise MigrationError(f"legacy oracle action {symbol!r} {key} must be an array")
        for index, raw_item in enumerate(raw_auxiliary):
            if not isinstance(raw_item, dict):
                raise MigrationError(f"legacy oracle action {symbol!r} {key}[{index}] is invalid")
            length = raw_item.get("length")
            if type(length) is not int or length < 1:
                raise MigrationError(
                    f"legacy oracle action {symbol!r} {key}[{index}] length is invalid"
                )
            maximum_oracle_payload_bytes += length
    oracle_alias = oracle.get("image") or function.get("retail_image_target")
    if not isinstance(oracle_alias, str) or _slug(oracle_alias) not in aliases:
        raise MigrationError(f"legacy oracle action {symbol!r} names unknown oracle image")
    address = oracle.get("address")
    try:
        oracle_address = int(address, 16) if isinstance(address, str) else -1
    except ValueError as exc:
        raise MigrationError(f"legacy oracle action {symbol!r} has invalid address") from exc
    if oracle_address < 0:
        raise MigrationError(f"legacy oracle action {symbol!r} has invalid address")
    preimage_key = (
        "expected_donor_body_sha256"
        if spec.get("pre_image") == "donor"
        else "expected_seed_body_sha256"
    )
    preimage_digest = _digest(function.get(preimage_key), f"{symbol} preimage digest")
    oracle_digest = _digest(function.get("expected_body_sha256"), f"{symbol} oracle digest")
    oracle_target = aliases[_slug(oracle_alias)]
    scope = Scope(target=target_id, translation_unit=tu_id, function=symbol)
    rationale = "Migrated, finite, disclosed oracle installation quarantine."
    dependencies = (dependency,) if dependency else ()
    proof_receipt_digest = Digest.from_bytes(canonical_json(proof_receipt))
    return LegacyOracleInstallIntervention.freeze(
        id=intervention_id,
        scope=scope,
        rationale=rationale,
        dependencies=dependencies,
        proof_receipt_digest=proof_receipt_digest,
        preimage_digest=preimage_digest,
        oracle_body_digest=oracle_digest,
        oracle_target=oracle_target,
        oracle_address=oracle_address,
        ranges=tuple(ranges),
        byte_count=sum(item.oracle_range.length for item in ranges),
        maximum_oracle_payload_bytes=maximum_oracle_payload_bytes,
    )


def _tool_id(path: str) -> str:
    return _slug(f"tool-{path.replace('/', '-')}")


def _toolchain_lock(manifest: Mapping[str, Any]) -> ToolchainLock:
    legacy = manifest.get("toolchain")
    if not isinstance(legacy, dict):
        raise MigrationError("legacy toolchain must be an object")
    profiles = legacy.get("backend_profiles")
    if not isinstance(profiles, dict):
        raise MigrationError("legacy toolchain lacks backend profiles")
    producer_items: list[Mapping[str, Any]] = []
    for profile in profiles.values():
        if not isinstance(profile, dict):
            continue
        for group in ("compiler_support_files", "producer_support_files"):
            items = profile.get(group)
            if isinstance(items, list):
                producer_items.extend(item for item in items if isinstance(item, dict))
    terminal = manifest.get("terminal_producers")
    if isinstance(terminal, dict) and isinstance(terminal.get("link"), dict):
        link = terminal["link"]
        # Project SDK libraries are source/build inputs, not binaries installed
        # beneath the selected compiler toolchain root.  They remain pinned in
        # the authoritative terminal-producer build plan.
        items = link.get("tools")
        if isinstance(items, list):
            producer_items.extend(item for item in items if isinstance(item, dict))
    codegen = legacy.get("codegen_path_contract")
    if isinstance(codegen, dict) and isinstance(codegen.get("compiler"), str):
        compiler = codegen["compiler"]
        marker = "/wine/"
        relative_compiler = (
            "wine/" + compiler.split(marker, 1)[1] if marker in compiler else Path(compiler).name
        )
        producer_items.append(
            {
                "path": relative_compiler,
                "sha256": legacy.get("compiler_sha256"),
                "roles": ["compiler"],
            }
        )
    backends = manifest.get("execution_backends")
    if isinstance(backends, dict) and isinstance(backends.get("profiles"), list):
        for backend_profile in backends["profiles"]:
            if not isinstance(backend_profile, dict):
                continue
            declared_files = backend_profile.get("toolchain_files")
            if not isinstance(declared_files, dict):
                continue
            producer_items.extend(
                {
                    "path": f"bin/{name}",
                    "sha256": digest,
                    "roles": ["compiler"],
                }
                for name, digest in declared_files.items()
                if isinstance(name, str) and isinstance(digest, str)
            )
    required_paths = {
        path.casefold(): path for path in TOOLCHAIN_PROFILES[MSVC_42].required_producers
    }
    required_runtime_paths = {
        path.casefold(): path for path in TOOLCHAIN_PROFILES[MSVC_42].required_runtime_files
    }
    tools_by_path: dict[str, LockedTool] = {}
    runtime_by_path: dict[str, LockedTool] = {}
    for item in producer_items:
        path = _relative(item.get("path"), "toolchain tool path")
        canonical_path = required_paths.get(path.casefold())
        if canonical_path is None and not path.casefold().startswith("bin/"):
            # Wrapper scripts and support data remain pinned in the build plan,
            # but are not loaded by the direct ExecutionBackend producer path.
            continue
        is_runtime = canonical_path is None
        selected_path = (
            required_runtime_paths.get(path.casefold(), path) if is_runtime else canonical_path
        )
        assert selected_path is not None
        path = selected_path
        raw_roles = item.get("roles")
        if not isinstance(raw_roles, list):
            role = item.get("role")
            raw_roles = [role] if isinstance(role, str) else []
        tool = LockedTool(
            id=_tool_id(path),
            path=path,
            digest=_digest(item.get("sha256"), f"toolchain tool {path}"),
            roles=tuple(sorted({_slug(role) for role in raw_roles if isinstance(role, str)})),
        )
        destination = runtime_by_path if is_runtime else tools_by_path
        destination_key = path.casefold() if is_runtime else path
        previous_tool = destination.get(destination_key)
        if previous_tool is not None and previous_tool.digest != tool.digest:
            raise MigrationError(f"toolchain path {path!r} has conflicting digests")
        destination[destination_key] = tool
    missing_tools = set(required_paths.values()) - set(tools_by_path)
    if missing_tools:
        raise MigrationError(
            f"legacy manifest lacks required toolchain producers: {sorted(missing_tools)}"
        )
    missing_runtime = set(required_runtime_paths) - set(runtime_by_path)
    if missing_runtime:
        raise MigrationError(
            "legacy manifest lacks required toolchain runtime files: "
            f"{sorted(required_runtime_paths[path] for path in missing_runtime)}"
        )
    if not tools_by_path:
        raise MigrationError("legacy manifest declares no output-relevant toolchain files")
    selected_profile = TOOLCHAIN_PROFILES[MSVC_42]
    source_pins = profile_source_pins_for_paths(
        selected_profile,
        (
            *(item.path for item in tools_by_path.values()),
            *(item.path for item in runtime_by_path.values()),
        ),
    )
    return ToolchainLock(
        schema_version=3,
        profile="msvc_4_2",
        release=MsvcRelease.V4_2,
        profile_sources=tuple(
            ToolchainProfileSource(
                repository=source.repository,
                revision=source.revision,
                paths=source.paths,
            )
            for source in source_pins
        ),
        tools=tuple(tools_by_path[path] for path in sorted(tools_by_path)),
        runtime_files=tuple(
            sorted(runtime_by_path.values(), key=lambda item: item.path.casefold())
        ),
        input_trees=(),
    )


def _migrated_link_authority(
    manifest: Mapping[str, Any],
) -> tuple[tuple[Literal["/DEBUG"], ...], tuple[ClassicSdkArchiveAuthority, ...]]:
    """Project only current analysis and SDK authority from the legacy link record."""

    terminal = manifest.get("terminal_producers")
    if terminal is None:
        return (), ()
    if not isinstance(terminal, Mapping):
        raise MigrationError("legacy terminal producers must be an object")
    raw_link = terminal.get("link")
    if raw_link is None:
        return (), ()
    if not isinstance(raw_link, Mapping):
        raise MigrationError("legacy terminal link policy must be an object")

    raw_options = raw_link.get("analysis_added_options", [])
    if not isinstance(raw_options, list) or any(item != "/DEBUG" for item in raw_options):
        raise MigrationError("legacy analysis link options must contain only /DEBUG")
    options = tuple(cast(Literal["/DEBUG"], item) for item in raw_options)
    raw_libraries = raw_link.get("project_sdk_libraries", [])
    if not isinstance(raw_libraries, list):
        raise MigrationError("legacy project SDK libraries must be an array")
    libraries: list[ClassicSdkArchiveAuthority] = []
    for index, item in enumerate(raw_libraries):
        if not isinstance(item, Mapping):
            raise MigrationError(f"legacy project SDK library {index} must be an object")
        path = item.get("path")
        sha256 = item.get("sha256")
        if not isinstance(path, str) or not isinstance(sha256, str):
            raise MigrationError(
                f"legacy project SDK library {index} lacks a path or SHA-256"
            )
        libraries.append(
            ClassicSdkArchiveAuthority(
                path=path,
                sha256=sha256,
            )
        )
    return options, tuple(libraries)


def _migrated_group_order(
    unit: Mapping[str, Any],
    *,
    source: str,
) -> ClassicGroupOrderPlan | None:
    """Translate a legacy TU mode only when it selects a real group-order operation."""

    raw_order = unit.get("group_order")
    if raw_order is None:
        return None
    if not isinstance(raw_order, list) or not raw_order:
        raise MigrationError(f"translation unit {source!r} has malformed group order")
    raw_orders = raw_order if isinstance(raw_order[0], list) else [raw_order]
    mode = unit.get("mode")
    operation: Literal["restore_comdat_group_order", "swap_comdat_group_order"]
    if mode == "swap_comdat_group_order":
        operation = "swap_comdat_group_order"
    elif mode in {"restore_comdat_group_order", "compose_equal_body_comdat"}:
        operation = "restore_comdat_group_order"
    else:
        raise MigrationError(
            f"translation unit {source!r} has no supported group-order operation"
        )
    return ClassicGroupOrderPlan(
        operation=operation,
        orders=tuple(
            tuple(order) if isinstance(order, list) else (order,)
            for order in raw_orders
        ),
    )


_CLASSIC_SOURCE_SUFFIXES = frozenset(
    {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc", ".inl"}
)


def _manifest_entry_bytes(source_root: Path, entry: SourceManifestEntry) -> bytes:
    root = source_root.resolve(strict=True)
    path = root.joinpath(*PurePosixPath(entry.path).parts)
    try:
        path.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise MigrationError(f"source manifest entry escapes the project: {entry.path!r}") from exc
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise MigrationError(f"source manifest entry is not regular: {entry.path!r}")
            payload = stream.read()
            after = os.fstat(stream.fileno())
    except OSError as exc:
        raise MigrationError(f"cannot read source manifest entry {entry.path!r}: {exc}") from exc
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_identity != after_identity:
        raise MigrationError(f"source manifest entry changed while read: {entry.path!r}")
    if len(payload) != entry.size or hashlib.sha256(payload).hexdigest() != entry.digest.value:
        raise MigrationError(f"source manifest entry differs from its pin: {entry.path!r}")
    return payload


def _contains_generator_kind(value: object, kind: str) -> bool:
    if isinstance(value, Mapping):
        return value.get("k") == kind or any(
            _contains_generator_kind(item, kind) for item in value.values()
        )
    if isinstance(value, list):
        return any(_contains_generator_kind(item, kind) for item in value)
    return False


def _normalized_legacy_overlay(
    overlay: Mapping[str, object],
    source_manifest: SourceManifestDocument,
    *,
    source_root: Path | None,
) -> dict[str, object]:
    has_member_probe = _contains_generator_kind(overlay, "member_probe")
    if not has_member_probe:
        return dict(overlay)
    if has_member_probe and (source_root is None or not source_manifest.complete):
        raise MigrationError(
            "member-probe overlay migration requires a complete physical source manifest"
        )

    clean_sources = (
        {
            entry.path: _manifest_entry_bytes(source_root, entry)
            for entry in source_manifest.entries
            if PurePosixPath(entry.path).suffix.casefold() in _CLASSIC_SOURCE_SUFFIXES
        }
        if has_member_probe and source_root is not None
        else {}
    )
    from reprobit.classic_overlay import SourceEditError
    from reprobit.migration_overlay import normalize_legacy_member_probe_return_types

    try:
        return normalize_legacy_member_probe_return_types(overlay, clean_sources)
    except SourceEditError as exc:
        raise MigrationError(f"cannot normalize legacy member probe: {exc}") from exc


def _migration_generator_leaves(value: object, *, context: str) -> tuple[dict[str, object], ...]:
    """Flatten one legacy typed generator in the runtime's leaf order."""

    if not isinstance(value, Mapping) or not isinstance(value.get("k"), str):
        raise MigrationError(f"{context} generator is malformed")
    normalized = {str(key): item for key, item in value.items()}
    if normalized["k"] != "seq":
        return (normalized,)
    raw_items = normalized.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        raise MigrationError(f"{context} generator sequence is empty")
    leaves: list[dict[str, object]] = []
    for index, raw_item in enumerate(raw_items):
        if not isinstance(raw_item, Mapping):
            raise MigrationError(f"{context} generator item {index} is malformed")
        child = {str(key): item for key, item in raw_item.items() if key != "line"}
        leaves.extend(
            _migration_generator_leaves(
                child,
                context=f"{context} generator item {index}",
            )
        )
    return tuple(leaves)


def _overlay_claim_requirements(
    outputs: list[object],
) -> dict[tuple[str, int], str]:
    """Name every v2 leaf whose ambiguity must be closed in v3."""

    requirements: dict[tuple[str, int], str] = {}
    seen_operations: set[str] = set()
    for output_index, raw_output in enumerate(outputs):
        if not isinstance(raw_output, Mapping):
            raise MigrationError(f"source overlay output {output_index} is malformed")
        path = _relative(raw_output.get("path"), f"source overlay output {output_index}")
        operations = raw_output.get("ops")
        if not isinstance(operations, list):
            raise MigrationError(f"source overlay output {path!r} has invalid operations")
        for operation_index, raw_operation in enumerate(operations):
            if not isinstance(raw_operation, Mapping):
                raise MigrationError(f"source overlay output {path!r} has an invalid operation")
            operation_id = raw_operation.get("id", f"{path}#{operation_index}")
            if not isinstance(operation_id, str) or not operation_id:
                raise MigrationError(f"source overlay output {path!r} has an invalid operation ID")
            if operation_id in seen_operations:
                raise MigrationError(f"source overlay operation is duplicated: {operation_id!r}")
            seen_operations.add(operation_id)
            leaves = _migration_generator_leaves(
                raw_operation.get("gen"),
                context=f"source overlay operation {operation_id!r}",
            )
            for leaf_index, leaf in enumerate(leaves):
                kind = leaf["k"]
                claim_kind = (
                    "function_scope"
                    if kind in _FUNCTION_CLAIM_GENERATORS
                    else "logical_header"
                    if kind == "include"
                    else None
                )
                if claim_kind is not None:
                    requirements[(operation_id, leaf_index)] = claim_kind
    return requirements


def _canonical_semantic_claims(
    bindings: Sequence[object],
    requirements: Mapping[tuple[str, int], str],
) -> list[dict[str, object]]:
    """Validate exact claim coverage and canonicalize only its ordering."""

    result: dict[tuple[str, int], dict[str, object]] = {}
    for index, raw_binding in enumerate(bindings):
        if not isinstance(raw_binding, Mapping):
            raise MigrationError(f"source-overlay semantic claim {index} is malformed")
        binding = {str(key): item for key, item in raw_binding.items()}
        operation = binding.get("operation")
        leaf = binding.get("leaf")
        kind = binding.get("kind")
        if (
            not isinstance(operation, str)
            or not operation
            or "\x00" in operation
            or not isinstance(leaf, int)
            or isinstance(leaf, bool)
            or leaf < 0
            or kind not in {"function_scope", "logical_header"}
        ):
            raise MigrationError(f"source-overlay semantic claim {index} is malformed")
        if kind == "logical_header":
            if set(binding) != {"kind", "leaf", "logical_path", "operation"}:
                raise MigrationError(f"source-overlay logical-header claim {index} is not closed")
            logical_path = binding.get("logical_path")
            if (
                not isinstance(logical_path, str)
                or _relative(
                    logical_path,
                    f"source-overlay semantic claim {index} logical path",
                )
                != logical_path
            ):
                raise MigrationError(f"source-overlay logical-header claim {index} is malformed")
        else:
            if set(binding) != {
                "bindings",
                "function",
                "kind",
                "leaf",
                "operation",
                "range_sha256",
                "range_size",
            }:
                raise MigrationError(f"source-overlay function-scope claim {index} is not closed")
            function = binding.get("function")
            range_digest = binding.get("range_sha256")
            range_size = binding.get("range_size")
            raw_scalar_bindings = binding.get("bindings")
            if (
                not isinstance(function, str)
                or not function
                or "\x00" in function
                or not isinstance(range_digest, str)
                or _SHA256.fullmatch(range_digest) is None
                or type(range_size) is not int
                or range_size <= 0
                or not isinstance(raw_scalar_bindings, list)
            ):
                raise MigrationError(f"source-overlay function-scope claim {index} is malformed")
            scalar_names: list[str] = []
            for scalar_index, raw_scalar in enumerate(raw_scalar_bindings):
                if not isinstance(raw_scalar, Mapping):
                    raise MigrationError(
                        "source-overlay function-scope scalar binding "
                        f"{index}:{scalar_index} is malformed"
                    )
                scalar = {str(key): item for key, item in raw_scalar.items()}
                identifier = scalar.get("identifier")
                type_spelling = scalar.get("type")
                if (
                    set(scalar) != {"identifier", "initialized", "type"}
                    or not isinstance(identifier, str)
                    or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", identifier) is None
                    or not isinstance(type_spelling, str)
                    or not type_spelling
                    or "\x00" in type_spelling
                    or not isinstance(scalar.get("initialized"), bool)
                ):
                    raise MigrationError(
                        "source-overlay function-scope scalar binding "
                        f"{index}:{scalar_index} is malformed"
                    )
                scalar_names.append(identifier)
            if scalar_names != sorted(scalar_names, key=str.casefold) or len(
                {item.casefold() for item in scalar_names}
            ) != len(scalar_names):
                raise MigrationError(
                    f"source-overlay function-scope claim {index} bindings are not canonical"
                )
        key = (operation, leaf)
        if key in result:
            raise MigrationError(f"source-overlay semantic claim is duplicated: {key!r}")
        result[key] = binding
    missing = sorted(set(requirements) - set(result))
    extra = sorted(set(result) - set(requirements))
    wrong = sorted(
        key
        for key in set(requirements) & set(result)
        if result[key].get("kind") != requirements[key]
    )
    if missing or extra or wrong:
        raise MigrationError(
            "source-overlay semantic claim coverage differs; "
            f"missing={missing}, extra={extra}, wrong_kind={wrong}"
        )
    return sorted(
        result.values(),
        key=lambda item: (
            str(item["operation"]).casefold(),
            cast(int, item["leaf"]),
            str(item["kind"]),
        ),
    )


def _logical_dos_path(value: Any) -> str:
    if not isinstance(value, str):
        raise MigrationError("legacy path contract lacks an absolute pinned path")
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts[1:])
    ):
        raise MigrationError("legacy path contract lacks a canonical absolute pinned path")
    try:
        return normalize_logical_path("Z:" + value.replace("/", "\\"))
    except ValueError as exc:
        raise MigrationError("legacy path contract cannot form a safe DOS seat") from exc


def _legacy_compiler_seats(contract: Mapping[str, Any]) -> dict[str, str]:
    """Derive the paths the schema-v2 runner actually exposed to MSVC.

    The legacy contract pins the checkout root and the runner workspace root.
    Its effective source and CMake build were always seated at ``src`` and
    ``build`` beneath that workspace.  Migrating the two parent roots directly
    would therefore change compiler-visible path spelling and length while
    retaining observations measured under different paths.
    """

    workspace = _legacy_workspace_root(contract)
    compiler = contract.get("compiler")
    if not isinstance(compiler, str):
        raise MigrationError("legacy path contract lacks compiler path")
    values = {
        "source": _logical_dos_path((workspace / "src").as_posix()),
        "build": _logical_dos_path((workspace / "build").as_posix()),
        "toolchain": _toolchain_root(compiler),
    }
    drives = {ntpath.splitdrive(value)[0].casefold() for value in values.values()}
    if len(drives) != 1:
        raise MigrationError("migrated logical roots do not share one DOS drive")
    folded = {name: value.casefold().rstrip("\\") for name, value in values.items()}
    for left_name, left in folded.items():
        for right_name, right in folded.items():
            if left_name >= right_name:
                continue
            if left == right or left.startswith(right + "\\") or right.startswith(left + "\\"):
                raise MigrationError(
                    "migrated logical roots overlap: "
                    f"{left_name}={values[left_name]!r}, "
                    f"{right_name}={values[right_name]!r}"
                )
    return values


def _toolchain_root(compiler: str) -> str:
    normalized = compiler.replace("\\", "/")
    marker = "/wine/"
    if marker not in normalized:
        raise MigrationError("cannot derive toolchain root from compiler path")
    return _logical_dos_path(normalized.split(marker, 1)[0])


def _toml(
    targets: list[dict[str, Any]],
    manifest: Mapping[str, Any],
    legacy_allowlist: tuple[LegacyAllowlistEntry, ...],
) -> bytes:
    toolchain = manifest.get("toolchain")
    contract = toolchain.get("codegen_path_contract") if isinstance(toolchain, dict) else None
    if not isinstance(contract, dict):
        raise MigrationError("legacy toolchain lacks compiler-visible path contract")
    source_root = contract.get("source_root")
    _logical_dos_path(source_root)
    values = _legacy_compiler_seats(contract)
    assert isinstance(source_root, str)
    project_id = _slug(PurePosixPath(source_root).name)
    terminal = manifest.get("terminal_producers")
    link = terminal.get("link") if isinstance(terminal, dict) else None
    standard_libraries = (
        link.get("generator_standard_libraries") if isinstance(link, dict) else None
    )
    raw_configuration = (
        standard_libraries.get("configuration") if isinstance(standard_libraries, dict) else None
    )
    if raw_configuration is not None and (
        not isinstance(raw_configuration, str) or not raw_configuration
    ):
        raise MigrationError("legacy link authority lacks its CMake configuration")
    policy = (
        AuthenticityPolicy.ALLOW_QUARANTINE.value
        if legacy_allowlist
        else AuthenticityPolicy.CLEAN.value
    )
    lines = [
        "schema_version = 3",
        f"project_id = {json.dumps(project_id)}",
        'state_dir = ".reprobit-state"',
        "",
        "[build]",
        'kind = "producer-graph"',
        "",
        "[toolchain]",
        'adapter = "classic-msvc"',
        'profile = "msvc_4_2"',
        'lock_file = "reprobit/toolchain.lock.json"',
        "",
        "[paths]",
        'id = "migrated-pinned-v1"',
        *(f"{key} = {json.dumps(value)}" for key, value in values.items()),
        "",
        "[verifier]",
        'kind = "literal"',
        "",
        "[authenticity]",
        f"policy = {json.dumps(policy)}",
    ]
    for entry in legacy_allowlist:
        lines.extend(
            [
                "",
                "[[authenticity.legacy_allowlist]]",
                f"intervention_id = {json.dumps(entry.intervention_id)}",
                "allowlist_digest = "
                + '{ algorithm = "sha256", value = '
                + json.dumps(entry.allowlist_digest.value)
                + " }",
                "proof_receipt_digest = "
                + '{ algorithm = "sha256", value = '
                + json.dumps(entry.proof_receipt_digest.value)
                + " }",
                f"range_count = {entry.range_count}",
                f"byte_count = {entry.byte_count}",
                (f"maximum_oracle_payload_bytes = {entry.maximum_oracle_payload_bytes}"),
            ]
        )
    lines.extend(
        [
            "",
            "[layout]",
            'build_plan = "reprobit/build-plan.json"',
            'interventions = "reprobit/interventions"',
            'proofs = "reprobit/proofs"',
            'oracles = "reprobit/oracles"',
        ]
    )
    for target in targets:
        lines.extend(
            [
                "",
                "[[targets]]",
                f"id = {json.dumps(target['id'])}",
                f"artifact = {json.dumps(target['artifact'])}",
                f"oracle = {json.dumps(target['oracle'])}",
            ]
        )
    return ("\n".join(lines) + "\n").encode()


def _project_recipe(
    *,
    intervention_id: str,
    target_id: str,
    build_target: str,
    family: ClassicRecipeFamily,
    values: Mapping[str, Any],
    rationale: str,
) -> tuple[ClassicRecipeIntervention, ClassicProofReceipt]:
    pins = _ProofPins({}, {})
    intervention = ClassicRecipeIntervention(
        id=intervention_id,
        family=family,
        role=ClassicRecipeRole.PROJECT,
        build_target=build_target,
        scope=Scope(target=target_id),
        parameters=_recipe_fields(values, pins, ""),
        rationale=rationale,
    )
    receipt = _proof_receipt(
        receipt_id=_stable_id("proof", intervention_id),
        intervention_id=intervention_id,
        family=family,
        pins=pins,
    )
    return intervention, receipt


def _locked_import_order(
    image: Mapping[str, Any],
    *,
    source_root: Path | None,
) -> Mapping[str, Any]:
    """Replace the v2 oracle-order marker with payload-free semantic metadata."""

    policy = image.get("iat_order")
    if policy != "retail_slot_order_v1":
        raise MigrationError(f"unsupported legacy IAT-order policy: {policy!r}")
    if source_root is None:
        raise MigrationError(
            "IAT-order migration requires the physical project root to lock semantic imports"
        )
    relative = _relative(image.get("original"), "IAT-order image original")
    path = source_root.joinpath(*PurePosixPath(relative).parts)
    if path.is_symlink() or not path.is_file():
        raise MigrationError(f"IAT-order image is absent or redirected: {relative!r}")
    payload = path.read_bytes()
    expected_digest = _digest(image.get("original_sha256"), "IAT-order image original digest")
    if hashlib.sha256(payload).hexdigest() != expected_digest.value:
        raise MigrationError(f"IAT-order image differs from its digest: {relative!r}")
    expected_size = image.get("original_size")
    if type(expected_size) is not int or expected_size != len(payload):
        raise MigrationError(f"IAT-order image differs from its size: {relative!r}")
    from reprobit.classic.pe_imports import capture_pe_import_order

    try:
        declaration = capture_pe_import_order(payload)
    except (ValueError, RuntimeError) as exc:
        raise MigrationError(f"cannot lock IAT order for {relative!r}: {exc}") from exc
    return {"import_order": declaration}


def _convert_v2_manifest(
    manifest: dict[str, Any],
    source_sha256: str,
    *,
    source_root: Path | None,
    semantic_claims: Mapping[str, Any] | None,
) -> MigrationOutput:
    if manifest.get("schema") != 2:
        raise MigrationError("conversion input must be a schema-v2 object")
    source_manifest = _source_manifest(manifest, source_root=source_root)
    source_manifest_pin = source_manifest_digest(source_manifest)
    units = manifest.get("translation_units")
    if not isinstance(units, list):
        raise MigrationError("legacy translation_units must be an array")
    targets, target_by_build, aliases = _target_declarations(manifest.get("images"))
    target_records = {target["id"]: target for target in targets}
    files: dict[PurePosixPath, bytes] = {}
    all_ids: set[str] = set()
    intervention_count = 0
    proof_count = 0
    legacy_allowlist: list[LegacyAllowlistEntry] = []
    plan_units: list[ClassicTranslationUnitPlan] = []
    shared_interventions: defaultdict[str, list[Intervention]] = defaultdict(list)
    shared_receipts: defaultdict[str, list[ClassicProofReceipt]] = defaultdict(list)
    compile_lane_owners: dict[tuple[str, str], tuple[str, ...]] | None = None

    for unit in units:
        if not isinstance(unit, dict):
            raise MigrationError("translation-unit entry is not an object")
        raw_build_target = unit.get("target")
        raw_source = unit.get("source")
        if not isinstance(raw_build_target, str) or not isinstance(raw_source, str):
            raise MigrationError("translation unit lacks target/source")
        build_target = _slug(raw_build_target)
        source = _relative(raw_source, "translation-unit source")
        target_id = _final_target(build_target, source, target_by_build)
        tu_id = _stable_id("tu", {"target": build_target, "source": source})
        source_digest = _digest(unit.get("source_sha256"), f"{source} source digest")
        plan_units.append(
            ClassicTranslationUnitPlan(
                id=tu_id,
                target_id=target_id,
                build_target=build_target,
                source=source,
                source_digest=source_digest,
                group_order=_migrated_group_order(unit, source=source),
            )
        )
        raw_donors = unit.get("donors", [])
        raw_functions = unit.get("functions", [])
        if not isinstance(raw_donors, list) or not isinstance(raw_functions, list):
            raise MigrationError(f"translation unit {source!r} has invalid lists")
        donor_entries: dict[str, dict[str, Any]] = {}
        for donor in raw_donors:
            if not isinstance(donor, dict) or not isinstance(donor.get("id"), str):
                raise MigrationError(f"donor entry for {source!r} lacks ID")
            legacy_id = donor["id"]
            previous = donor_entries.get(legacy_id)
            if previous is not None and previous != donor:
                raise MigrationError(f"conflicting donor definition {legacy_id!r}")
            donor_entries[legacy_id] = donor
        donor_ids = {
            legacy_id: _stable_id(
                "donor",
                {"legacy_id": legacy_id, "target": build_target, "source": source},
            )
            for legacy_id in donor_entries
        }
        beneficiary_map: defaultdict[str, dict[tuple[str, str, str], Scope]] = defaultdict(dict)
        interventions: list[Intervention] = []
        receipts: list[ClassicProofReceipt] = []

        for function in raw_functions:
            if not isinstance(function, dict):
                raise MigrationError(f"function entry for {source!r} is invalid")
            symbol = function.get("mangled")
            kind = function.get("splice_class")
            if not isinstance(symbol, str) or not isinstance(kind, str):
                raise MigrationError(f"function entry for {source!r} lacks identity")
            family = _family(kind, f"function {symbol!r}")
            legacy_donor = function.get("donor")
            dependency = donor_ids.get(legacy_donor) if isinstance(legacy_donor, str) else None
            if isinstance(legacy_donor, str) and dependency is None:
                raise MigrationError(f"function {symbol!r} names unknown donor {legacy_donor!r}")
            scope = Scope(target=target_id, translation_unit=tu_id, function=symbol)
            intervention_id = _stable_id(
                "fn",
                {
                    "target": build_target,
                    "source": source,
                    "symbol": symbol,
                    "family": kind,
                    "donor": dependency,
                },
            )
            pins = _ProofPins({}, {})
            if family is ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION:
                for key in sorted(function):
                    if key not in {"mangled", "splice_class", "donor"}:
                        path = key
                        if _is_forbidden_recipe_name(key):
                            _record_redaction(pins, path, function[key])
                        else:
                            _record_expected(pins, path, function[key])
                proof_receipt = _proof_receipt(
                    receipt_id=_stable_id("proof", intervention_id),
                    intervention_id=intervention_id,
                    family=family,
                    pins=pins,
                )
                legacy_intervention = _legacy_install(
                    intervention_id=intervention_id,
                    target_id=target_id,
                    tu_id=tu_id,
                    symbol=symbol,
                    function=function,
                    dependency=dependency,
                    aliases=aliases,
                    proof_receipt=proof_receipt,
                )
                intervention: Intervention = legacy_intervention
                legacy_allowlist.append(
                    LegacyAllowlistEntry(
                        intervention_id=legacy_intervention.id,
                        allowlist_digest=legacy_intervention.allowlist_digest,
                        proof_receipt_digest=legacy_intervention.proof_receipt_digest,
                        range_count=len(legacy_intervention.ranges),
                        byte_count=legacy_intervention.byte_count,
                        maximum_oracle_payload_bytes=(
                            legacy_intervention.maximum_oracle_payload_bytes
                        ),
                    )
                )
            else:
                values = {
                    key: value
                    for key, value in function.items()
                    if key not in {"mangled", "splice_class", "donor"}
                }
                _migrate_donor_references(
                    values,
                    donor_ids,
                    context=f"function {symbol!r}",
                )
                rationale = values.pop("rationale", "Migrated compiler-entropy intervention.")
                if not isinstance(rationale, str) or not rationale:
                    rationale = "Migrated compiler-entropy intervention."
                intervention = ClassicRecipeIntervention(
                    id=intervention_id,
                    family=family,
                    role=ClassicRecipeRole.FUNCTION,
                    build_target=build_target,
                    symbol=symbol,
                    scope=scope,
                    parameters=_recipe_fields(values, pins, ""),
                    rationale=rationale,
                    dependencies=(dependency,) if dependency else (),
                )
                proof_receipt = _proof_receipt(
                    receipt_id=_stable_id("proof", intervention_id),
                    intervention_id=intervention_id,
                    family=family,
                    pins=pins,
                )
            interventions.append(intervention)
            receipts.append(proof_receipt)
            if dependency:
                key = (scope.target, scope.translation_unit or "", scope.function or "")
                beneficiary_map[dependency][key] = scope

        for legacy_id, donor in donor_entries.items():
            recipe = donor.get("recipe")
            if not isinstance(recipe, dict):
                raise MigrationError(f"donor {legacy_id!r} recipe is invalid")
            family = _family(recipe.get("kind"), f"donor {legacy_id!r}")
            if family is ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION:
                raise MigrationError("oracle installation cannot be disguised as a donor recipe")
            pins = _ProofPins({}, {})
            values = {key: value for key, value in recipe.items() if key != "kind"}
            required_define = _migrate_donor_compile_lane(
                values,
                family,
                context=f"donor {legacy_id!r}",
            )
            donor_build_target = build_target
            if required_define is not None:
                if compile_lane_owners is None:
                    compile_lane_owners = _legacy_compile_lane_owners(manifest)
                raw_donor_source = values.get("donor_source", source)
                donor_source = _relative(
                    raw_donor_source,
                    f"donor {legacy_id!r} compile source",
                )
                donor_build_target = _legacy_compile_lane_owner(
                    compile_lane_owners,
                    source=donor_source,
                    required_define=required_define,
                    context=f"donor {legacy_id!r}",
                )
            rationale = values.pop("authenticity_rationale", "Migrated compiler donor.")
            if not isinstance(rationale, str) or not rationale:
                rationale = "Migrated compiler donor."
            donor_id = donor_ids[legacy_id]
            intervention = ClassicRecipeIntervention(
                id=donor_id,
                family=family,
                role=ClassicRecipeRole.DONOR,
                build_target=donor_build_target,
                scope=Scope(target=target_id, translation_unit=tu_id),
                parameters=_recipe_fields(values, pins, ""),
                rationale=rationale,
                beneficiaries=tuple(
                    beneficiary_map[donor_id][key] for key in sorted(beneficiary_map[donor_id])
                ),
            )
            interventions.append(intervention)
            status = donor.get("status")
            authenticity = donor.get("authenticity")
            receipts.append(
                _proof_receipt(
                    receipt_id=_stable_id("proof", donor_id),
                    intervention_id=donor_id,
                    family=family,
                    pins=pins,
                    status=status if isinstance(status, str) and status else None,
                    authenticity=(
                        authenticity if isinstance(authenticity, str) and authenticity else None
                    ),
                )
            )
        for intervention in interventions:
            if intervention.id in all_ids:
                raise MigrationError(f"duplicate migrated intervention ID: {intervention.id}")
            all_ids.add(intervention.id)
        shard_name = f"{target_id}--{tu_id}.json"
        files[PurePosixPath("reprobit/interventions/tus") / shard_name] = _model_bytes(
            InterventionDocument(
                schema_version=3,
                target_id=target_id,
                translation_unit_id=tu_id,
                source=source,
                source_digest=source_digest,
                build_target=build_target,
                interventions=tuple(sorted(interventions, key=lambda item: item.id)),
            )
        )
        files[PurePosixPath("reprobit/proofs/tus") / shard_name] = _model_bytes(
            ProofDocument(
                schema_version=3,
                target_id=target_id,
                translation_unit_id=tu_id,
                expected_observations=tuple(sorted(receipts, key=lambda item: item.id)),
            )
        )
        intervention_count += len(interventions)
        proof_count += len(receipts)

    for target_id, target in target_records.items():
        image = target["image"]
        build_target = target["build_target"]
        specs: list[tuple[ClassicRecipeFamily, str, Mapping[str, Any]]] = []
        metadata = {key: image[key] for key in ("link_time", "resource_time") if key in image}
        if metadata:
            specs.append((ClassicRecipeFamily.IMAGE_METADATA, "metadata", metadata))
        if "iat_order" in image:
            specs.append(
                (
                    ClassicRecipeFamily.IMAGE_LINK_ORDER,
                    "iat-order",
                    _locked_import_order(image, source_root=source_root),
                )
            )
        for key in ("text_repack", "rdata_pool_repack"):
            if key in image:
                specs.append(
                    (
                        ClassicRecipeFamily.IMAGE_BINARY_REPACK,
                        key.replace("_", "-"),
                        {key: image[key]},
                    )
                )
        for family, label, project_values in specs:
            intervention, receipt = _project_recipe(
                intervention_id=_stable_id("project", {"target": target_id, "kind": label}),
                target_id=target_id,
                build_target=build_target,
                family=family,
                values=project_values,
                rationale=f"Migrated image-level {label} intervention.",
            )
            shared_interventions[target_id].append(intervention)
            shared_receipts[target_id].append(receipt)

    overlay = manifest.get("source_overlay")
    if not isinstance(overlay, dict):
        raise MigrationError("legacy source_overlay must be an object")
    if "semantic_claims" in overlay:
        raise MigrationError(
            "schema-v2 migration input must remain immutable: remove "
            "source_overlay.semantic_claims and pass the one-off reviewed file with "
            "--semantic-claims"
        )
    overlay = _normalized_legacy_overlay(
        cast(Mapping[str, object], overlay),
        source_manifest,
        source_root=source_root,
    )
    outputs = overlay.get("outputs")
    graph = overlay.get("graph")
    if not isinstance(outputs, list) or not isinstance(graph, dict):
        raise MigrationError("legacy source_overlay has invalid shape")
    claim_requirements = _overlay_claim_requirements(cast(list[object], outputs))
    overlay_groups: defaultdict[str, list[Any]] = defaultdict(list)
    overlay_operation_targets: dict[str, str] = {}
    for output in outputs:
        if not isinstance(output, dict) or not isinstance(output.get("path"), str):
            raise MigrationError("legacy source overlay output is invalid")
        path = _relative(output["path"], "source overlay output")
        first = _slug(PurePosixPath(path).parts[0])
        if first not in target_records:
            if len(target_records) != 1:
                raise MigrationError(f"cannot associate source overlay output {path!r}")
            first = next(iter(target_records))
        overlay_groups[first].append(output)
        operations = output.get("ops")
        if not isinstance(operations, list):
            raise MigrationError(f"source overlay output {path!r} has invalid operations")
        for index, operation in enumerate(operations):
            if not isinstance(operation, dict):
                raise MigrationError(f"source overlay output {path!r} has an invalid operation")
            operation_id = operation.get("id", f"{path}#{index}")
            if not isinstance(operation_id, str) or not operation_id:
                raise MigrationError(f"source overlay output {path!r} has an invalid operation ID")
            if operation_id in overlay_operation_targets:
                raise MigrationError(f"source overlay operation is duplicated: {operation_id!r}")
            overlay_operation_targets[operation_id] = first

    semantic_claim_groups: defaultdict[str, list[Any]] = defaultdict(list)
    raw_semantic_claims = semantic_claims
    if raw_semantic_claims is not None:
        if not isinstance(raw_semantic_claims, dict) or set(raw_semantic_claims) != {
            "bindings",
            "schema",
        }:
            raise MigrationError("legacy source-overlay semantic claims have invalid shape")
        semantic_claim_schema = raw_semantic_claims.get("schema")
        bindings = raw_semantic_claims.get("bindings")
        if semantic_claim_schema != 1 or not isinstance(bindings, list):
            raise MigrationError("legacy source-overlay semantic claims are malformed")
        for binding in bindings:
            if not isinstance(binding, dict) or not isinstance(binding.get("operation"), str):
                raise MigrationError("legacy source-overlay semantic claim is malformed")
            operation_id = binding["operation"]
            if operation_id not in overlay_operation_targets:
                raise MigrationError(
                    f"source-overlay semantic claim names an unknown operation: {operation_id!r}"
                )
        semantic_bindings = _canonical_semantic_claims(bindings, claim_requirements)
    elif claim_requirements:
        required = sorted(
            f"{operation}[{leaf}]={kind}" for (operation, leaf), kind in claim_requirements.items()
        )
        raise MigrationError(
            "legacy source overlay requires an explicit semantic-claims sidecar; "
            "pass --semantic-claims with one reviewed binding for each required generator "
            "leaf: " + ", ".join(required)
        )
    else:
        semantic_bindings = []
    for binding in semantic_bindings:
        operation_id = cast(str, binding["operation"])
        target_id = overlay_operation_targets[operation_id]
        semantic_claim_groups[target_id].append(binding)
    graph_groups: defaultdict[str, list[Any]] = defaultdict(list)
    generated = graph.get("generated_tus", [])
    if not isinstance(generated, list):
        raise MigrationError("source overlay generated_tus is invalid")
    for item in generated:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise MigrationError("source overlay generated TU is invalid")
        first = _slug(PurePosixPath(item["path"].replace("\\", "/")).parts[0])
        if first not in target_records:
            raise MigrationError(f"cannot associate generated TU {item['path']!r}")
        graph_groups[first].append(item)
    link_admissions = graph.get("link_admissions", [])
    if link_admissions:
        raise MigrationError("non-empty link admissions need explicit target mapping")
    overlay_intervention_ids: list[str] = []
    for target_id in sorted(set(overlay_groups) | set(graph_groups)):
        values = {
            "schema": overlay.get("schema"),
            "outputs": overlay_groups[target_id],
            "graph": {"generated_tus": graph_groups[target_id], "link_admissions": []},
            "semantic_claims": {
                "schema": 1,
                "bindings": semantic_claim_groups[target_id],
            },
        }
        intervention, receipt = _project_recipe(
            intervention_id=_stable_id("project", {"target": target_id, "kind": "source-overlay"}),
            target_id=target_id,
            build_target=target_records[target_id]["build_target"],
            family=ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH,
            values=values,
            rationale="Migrated typed source-overlay graph.",
        )
        shared_interventions[target_id].append(intervention)
        shared_receipts[target_id].append(receipt)
        overlay_intervention_ids.append(intervention.id)

    for target in targets:
        target_id = target["id"]
        for intervention in shared_interventions[target_id]:
            if intervention.id in all_ids:
                raise MigrationError(f"duplicate migrated intervention ID: {intervention.id}")
            all_ids.add(intervention.id)
        files[PurePosixPath("reprobit/interventions") / f"shared-{target_id}.json"] = _model_bytes(
            InterventionDocument(
                schema_version=3,
                target_id=target_id,
                build_target=target["build_target"],
                interventions=tuple(
                    sorted(shared_interventions[target_id], key=lambda item: item.id)
                ),
            )
        )
        files[PurePosixPath("reprobit/proofs") / f"shared-{target_id}.proof.json"] = _model_bytes(
            ProofDocument(
                schema_version=3,
                target_id=target_id,
                expected_observations=tuple(
                    sorted(shared_receipts[target_id], key=lambda item: item.id)
                ),
            )
        )
        intervention_count += len(shared_interventions[target_id])
        proof_count += len(shared_receipts[target_id])

    target_gates: list[ClassicTargetGate] = []
    for target in targets:
        image = target["image"]
        target_id = target["id"]
        raw_row_digest = image.get("row_identity_sha256")
        row_digest = (
            _digest(raw_row_digest, f"image {target_id} row identity")
            if raw_row_digest is not None
            else None
        )
        row_count = image.get("required_row_count")
        if row_count is not None and type(row_count) is not int:
            raise MigrationError(f"image {target_id} row count is invalid")
        oracle = OracleDocument(
            schema_version=3,
            target_id=target_id,
            image_size=image.get("original_size"),
            image_digest=_digest(image.get("original_sha256"), f"image {target_id}"),
            required_row_count=row_count,
            row_identity_digest=row_digest,
        )
        files[PurePosixPath("reprobit/oracles") / f"{target_id}.json"] = _model_bytes(oracle)
        target_gates.append(
            ClassicTargetGate(
                target_id=target_id,
                build_target=target["build_target"],
            )
        )

    raw_archives = manifest.get("archives", [])
    if not isinstance(raw_archives, list):
        raise MigrationError("legacy archives must be an array")
    archive_authorities = tuple(
        ClassicArchiveAuthority.model_validate_json(canonical_json(item)) for item in raw_archives
    )
    analysis_link_options, project_sdk_libraries = _migrated_link_authority(manifest)
    build_plan = BuildPlanDocument(
        schema_version=3,
        source_manifest_digest=source_manifest_pin,
        translation_units=tuple(sorted(plan_units, key=lambda item: item.id)),
        source_overlay_digest=Digest.from_bytes(_canonical(overlay)),
        source_overlay_interventions=tuple(sorted(overlay_intervention_ids)),
        archives=archive_authorities,
        analysis_link_options=analysis_link_options,
        project_sdk_libraries=project_sdk_libraries,
        target_gates=tuple(sorted(target_gates, key=lambda item: item.target_id)),
    )
    files[PurePosixPath("reprobit/build-plan.json")] = _model_bytes(build_plan)
    files[PurePosixPath("reprobit/source-manifest.json")] = _model_bytes(source_manifest)
    files[PurePosixPath("reprobit/toolchain.lock.json")] = _model_bytes(_toolchain_lock(manifest))
    files[PurePosixPath("reprobit.toml")] = _toml(
        targets,
        manifest,
        tuple(sorted(legacy_allowlist, key=lambda item: item.intervention_id)),
    )
    return MigrationOutput(files, source_sha256, intervention_count, proof_count)


def convert_v2_manifest(
    manifest: dict[str, Any],
    source_sha256: str,
    *,
    source_root: Path | None = None,
    semantic_claims_path: Path | None = None,
) -> MigrationOutput:
    """Convert v2 data, translating model errors into migration failures."""

    try:
        return _convert_v2_manifest(
            manifest,
            source_sha256,
            source_root=source_root,
            semantic_claims=_load_semantic_claims_sidecar(semantic_claims_path),
        )
    except MigrationError:
        raise
    except (ValidationError, TypeError, ValueError) as exc:
        raise MigrationError(f"migration generated invalid schema-v3 data: {exc}") from exc


def migration_output(
    path: Path,
    *,
    semantic_claims_path: Path | None = None,
) -> MigrationOutput:
    manifest, source_sha256 = load_legacy_manifest(path)
    declared = tuple(_declared_source_pins(manifest))
    project_root = next(
        (
            candidate
            for candidate in (path.resolve().parent, *path.resolve().parents)
            if any(
                candidate.joinpath(*PurePosixPath(relative).parts).is_file()
                for relative in declared
            )
        ),
        None,
    )
    if project_root is None:
        raise MigrationError("cannot locate the physical project root for source receipts")
    return convert_v2_manifest(
        manifest,
        source_sha256,
        source_root=project_root,
        semantic_claims_path=semantic_claims_path,
    )


__all__ = [
    "MigrationError",
    "MigrationOutput",
    "convert_v2_manifest",
    "load_legacy_manifest",
    "migration_output",
    "validate_migration_files",
]
