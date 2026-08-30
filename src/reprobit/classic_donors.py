"""Closed, oracle-free source preparation for classic compiler donors.

The binary composition layer consumes freshly compiled COFF objects.  This
module owns the source side of that boundary: it validates one declarative
``ClassicRecipeIntervention`` and produces every private file and compiler
addition needed to compile its donor.  It never opens a project file, accepts
an oracle, or carries an opaque byte literal in recipe metadata.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast

from reprobit.model import Digest
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)
from reprobit.strict_json import JsonValue, canonical_json

if TYPE_CHECKING:
    from reprobit.classic_overlay_types import ClassicOverlayOutputReceipt


class DonorSourceError(ValueError):
    """A donor declaration or its authenticated source input is invalid."""


DONOR_FAMILIES = frozenset(
    {
        ClassicRecipeFamily.DECLARATION_SHAPE,
        ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        ClassicRecipeFamily.FORWARD_DECLARATION_RUN,
        ClassicRecipeFamily.PAD_SHAPE,
        ClassicRecipeFamily.EXTERN_RUN_PAIR,
        ClassicRecipeFamily.FORWARD_RUN_WITH_SHAPE,
        ClassicRecipeFamily.DECLARATION_RUN_TRIPLE,
        ClassicRecipeFamily.PREFIX_FORWARD_AFTER_INCLUDES_EXTERN,
    }
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_CONSTRAINT_PATH = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)(?:\[([0-9]+)\])?")
_FORBIDDEN_EXACT_KEYS = frozenset(
    {
        "bytes",
        "payload",
        "body",
        "oracle_path",
        "reference_path",
        "callable",
        "script",
        "python",
        "template",
    }
)
_FORBIDDEN_SUFFIXES = ("_bytes", "_payload", "_body")
_ROLE_POLICIES = frozenset(
    {
        "cross_tu_complete_target_only_v1",
        "retail_exact_instruction_mosaic_fpo_only_v1",
        "retail_exact_instruction_permutation_eh_closure_only_v1",
        "retail_exact_instruction_permutation_fpo_only_v1",
    }
)
_PROJECTIONS = frozenset({"source_root_mirror_v1", "source_root_mirror_only_v1"})


def _digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def _fail(message: str) -> None:
    raise DonorSourceError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _sha(value: object, label: str) -> str:
    _require(isinstance(value, str) and _SHA256.fullmatch(value) is not None, label)
    return cast(str, value)


def _integer(
    value: object,
    label: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    _require(type(value) is int, f"{label} must be an exact integer")
    result = cast(int, value)
    if minimum is not None:
        _require(result >= minimum, f"{label} is below {minimum}")
    if maximum is not None:
        _require(result <= maximum, f"{label} exceeds {maximum}")
    return result


def _identifier(value: object, label: str) -> str:
    _require(
        isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None,
        f"{label} must be a C/C++ identifier",
    )
    return cast(str, value)


def _logical_path(value: object, label: str) -> str:
    _require(isinstance(value, str) and value != "", f"{label} must be a path")
    raw = cast(str, value)
    _require("\0" not in raw and "\\" not in raw, f"{label} is not normalized")
    path = PurePosixPath(raw)
    _require(
        not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts),
        f"{label} leaves the source root",
    )
    return path.as_posix()


def _exact_keys(
    value: Mapping[str, object],
    expected: frozenset[str] | set[str],
    label: str,
    *,
    optional: frozenset[str] | set[str] = frozenset(),
) -> None:
    names = set(value)
    unknown = names - set(expected)
    missing = set(expected) - names - set(optional)
    _require(
        not unknown and not missing,
        f"{label} schema differs; unknown={sorted(unknown)} missing={sorted(missing)}",
    )


def _reject_payload_fields(value: object, label: str) -> None:
    """Recursively reject recipe-shaped payload smuggling.

    Digest and geometry fields such as ``expected_body_sha256`` are safe; a
    leaf actually named ``body`` or ending in ``_body`` is not.  Bytes-like
    values are always explicit compiler inputs and therefore never valid JSON
    declaration data.
    """

    pending: list[tuple[object, str]] = [(value, label)]
    seen: set[int] = set()
    while pending:
        current, path = pending.pop()
        if isinstance(current, (bytes, bytearray, memoryview)):
            _fail(f"{path} embeds a byte payload")
        if isinstance(current, Mapping):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            for raw_key, child in current.items():
                _require(isinstance(raw_key, str), f"{path} has a non-string key")
                key = cast(str, raw_key)
                normalized = key.casefold().replace("-", "_")
                forbidden = (
                    normalized in _FORBIDDEN_EXACT_KEYS
                    or normalized.endswith(_FORBIDDEN_SUFFIXES)
                    or "oracle_path" in normalized
                    or "reference_path" in normalized
                )
                _require(not forbidden, f"{path}.{key} is a payload-shaped field")
                pending.append((child, f"{path}.{key}"))
        elif isinstance(current, Sequence) and not isinstance(current, str):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            pending.extend((child, f"{path}[{index}]") for index, child in enumerate(current))


def _json_equal(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        right_dict = cast(dict[object, object], right)
        return left.keys() == right_dict.keys() and all(
            _json_equal(left[key], right_dict[key]) for key in left
        )
    if isinstance(left, list):
        right_list = cast(list[object], right)
        return len(left) == len(right_list) and all(
            _json_equal(a, b) for a, b in zip(left, right_list, strict=True)
        )
    return left == right


def _freeze(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(child) for child in value)
    return value


def _thaw(value: object) -> JsonValue:
    if isinstance(value, Mapping):
        return {str(key): _thaw(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw(child) for child in value]
    return cast(JsonValue, value)


def _constraint_parts(path: str) -> tuple[tuple[str, int | None], ...]:
    pieces = path.split(".")
    parsed: list[tuple[str, int | None]] = []
    for piece in pieces:
        match = _CONSTRAINT_PATH.fullmatch(piece)
        _require(match is not None, f"unsupported candidate-constraint path: {path!r}")
        assert match is not None
        parsed.append((match.group(1), int(match.group(2)) if match.group(2) else None))
    return tuple(parsed)


def _install_constraint(root: dict[str, Any], path: str, value: JsonValue) -> None:
    parts = _constraint_parts(path)
    current: Any = root
    for position, (name, index) in enumerate(parts):
        final = position == len(parts) - 1
        _require(isinstance(current, dict), f"candidate constraint {path!r} crosses a scalar")
        if index is None:
            if final:
                if name in current:
                    _require(
                        _json_equal(current[name], value),
                        f"candidate constraint {path!r} conflicts with recipe intent",
                    )
                else:
                    current[name] = deepcopy(value)
                return
            child = current.get(name)
            if child is None:
                child = {}
                current[name] = child
            current = child
            continue
        sequence = current.get(name)
        _require(isinstance(sequence, list), f"candidate constraint {path!r} lacks its array")
        _require(index < len(sequence), f"candidate constraint {path!r} leaves its array")
        if final:
            _require(
                _json_equal(sequence[index], value),
                f"candidate constraint {path!r} conflicts with recipe intent",
            )
            return
        current = sequence[index]


@dataclass(frozen=True, slots=True)
class CandidateConstraints:
    """One intervention's intent merged with its immutable expected pins."""

    intervention_id: str
    family: ClassicRecipeFamily
    receipt_id: str
    values: Mapping[str, object]
    digest: Digest

    def materialize(self) -> dict[str, JsonValue]:
        """Return an isolated native-JSON copy for the candidate producer."""

        return cast(dict[str, JsonValue], _thaw(self.values))


def merge_candidate_constraints(
    intervention: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
) -> CandidateConstraints:
    """Merge only ``expected_values`` from one cross-checked proof receipt.

    Redaction entries are deliberately not exposed to the producer.  They are
    migration audit records, not candidate inputs.
    """

    _require(
        receipt.intervention_id == intervention.id,
        "proof receipt names a different intervention",
    )
    _require(receipt.family is intervention.family, "proof receipt family differs")
    parameters: dict[str, Any] = {
        field.name: deepcopy(field.value) for field in intervention.parameters
    }
    _reject_payload_fields(parameters, "classic recipe")
    _reject_payload_fields(receipt.expected_values, "candidate constraints")
    for path in sorted(receipt.expected_values):
        _install_constraint(parameters, path, receipt.expected_values[path])
    canonical = cast(dict[str, JsonValue], deepcopy(parameters))
    return CandidateConstraints(
        intervention.id,
        intervention.family,
        receipt.id,
        cast(Mapping[str, object], _freeze(parameters)),
        Digest.from_bytes(canonical_json(canonical)),
    )


def matching_candidate_constraints(
    intervention: ClassicRecipeIntervention,
    receipts: Iterable[ClassicProofReceipt],
) -> CandidateConstraints:
    """Find exactly one receipt for ``intervention`` and merge its pins."""

    matches: list[ClassicProofReceipt] = []
    for receipt in receipts:
        if receipt.intervention_id != intervention.id:
            continue
        _require(receipt.family is intervention.family, "proof receipt family differs")
        matches.append(receipt)
    _require(len(matches) == 1, f"intervention {intervention.id!r} requires one proof receipt")
    return merge_candidate_constraints(intervention, matches[0])


def _shape_suffix(number: int, width: int) -> str:
    characters: list[str] = []
    for _ in range(width):
        characters.append(chr(ord("a") + number % 26))
        number //= 26
    return "".join(reversed(characters))


def generate_forward_run(prefix: str, count: int, width: int) -> bytes:
    prefix = _identifier(prefix, "forward-run prefix")
    _integer(count, "forward-run count", minimum=1, maximum=999)
    _integer(width, "forward-run width", minimum=1, maximum=3)
    _require(count <= 10**width, "forward-run width cannot represent its count")
    return "".join(f"class {prefix}{number:0{width}d};\n" for number in range(count)).encode(
        "ascii"
    )


def generate_extern_run(prefix: str, count: int, width: int) -> bytes:
    prefix = _identifier(prefix, "extern-run prefix")
    _integer(count, "extern-run count", minimum=1, maximum=999)
    _integer(width, "extern-run width", minimum=1, maximum=3)
    _require(count <= 10**width, "extern-run width cannot represent its count")
    return "".join(f"extern int {prefix}{number:0{width}d};\n" for number in range(count)).encode(
        "ascii"
    )


def generate_declaration_shape(classes: int, functions: int) -> bytes:
    _integer(classes, "declaration-shape classes", minimum=1, maximum=10)
    _integer(
        functions,
        "declaration-shape functions",
        minimum=classes,
        maximum=10 * classes,
    )
    counts = [1] * classes
    for index in range(functions - classes):
        counts[index % classes] += 1
    lines = [
        "// Generated declaration-only entropy shape. Emits no code or data.",
        f"// Shape: classes={classes} functions={functions}",
        "",
    ]
    function_number = 0
    for class_number, count in enumerate(counts):
        lines.extend([f"class Class{chr(ord('A') + class_number)}aaaaa {{", "public:"])
        for _ in range(count):
            function_name = (
                "Function"
                + chr(ord("A") + function_number % 26)
                + _shape_suffix(function_number // 26, 7)
            )
            lines.append(f"\tinline void {function_name}() {{}}")
            function_number += 1
        lines.extend(["};", ""])
    return ("\n".join(lines) + "\n").encode("ascii")


def generate_pad_shape(classes: int, functions_per_class: int) -> bytes:
    _integer(classes, "pad-shape classes", minimum=1, maximum=99)
    _integer(
        functions_per_class,
        "pad-shape functions per class",
        minimum=1,
        maximum=99,
    )
    parts: list[str] = []
    for class_number in range(classes):
        lines = [f"class ClassPad{class_number:02d} {{"]
        for function_number in range(functions_per_class):
            lines.append(
                f"\tinline void FunctionPad{class_number:02d}x{function_number:02d}() {{}}"
            )
        lines.append("};")
        parts.append("\n".join(lines))
    return ("\n\n".join(parts) + "\n").encode("ascii")


class DonorIncludeProjection(StrEnum):
    NONE = "none"
    SOURCE_ROOT_MIRROR = "source_root_mirror_v1"
    SOURCE_ROOT_MIRROR_ONLY = "source_root_mirror_only_v1"


@dataclass(frozen=True, slots=True)
class DonorCompilerAdditions:
    """Private path additions derived for an authenticated donor compile."""

    force_includes: tuple[str, ...] = ()
    include_directories: tuple[str, ...] = ()
    include_projection: DonorIncludeProjection = DonorIncludeProjection.NONE


@dataclass(frozen=True, slots=True)
class DonorRecipeValidation:
    family: ClassicRecipeFamily
    parameters: Mapping[str, object]
    compiler_seat: str
    include_projection: DonorIncludeProjection
    generated_declarations: bytes | None
    force_include_payload: bytes | None
    carrier_identifiers: frozenset[str]


@dataclass(frozen=True, slots=True)
class DonorCompileReceipt:
    intervention_id: str
    family: ClassicRecipeFamily
    constraints_digest: Digest
    input_digests: Mapping[str, str]
    output_digests: Mapping[str, str]
    compiler_additions_digest: Digest
    rendering_digest: Digest


@dataclass(frozen=True, slots=True)
class DonorCompileRequest:
    """A complete, private donor compile input; all byte fields are fresh or derived."""

    intervention_id: str
    compiler_seat: str
    family: ClassicRecipeFamily
    build_target: str
    logical_source: str
    staged_source: str
    files: Mapping[str, bytes]
    logical_outputs: Mapping[str, bytes]
    compiler_additions: DonorCompilerAdditions
    carrier_identifiers: frozenset[str]
    receipt: DonorCompileReceipt
    overlay_receipts: tuple[ClassicOverlayOutputReceipt, ...] = ()


def donor_requires_dependency_tracking(
    request: DonorCompileRequest,
    *,
    owning_build_target: str,
    owning_logical_source: str,
) -> bool:
    """Return whether a donor reads outside its owning compiler lane."""

    request_lane = (request.build_target.casefold(), request.logical_source.casefold())
    owning_lane = (owning_build_target.casefold(), owning_logical_source.casefold())
    return (
        request.compiler_additions.include_projection is not DonorIncludeProjection.NONE
        or request_lane != owning_lane
    )


def _legacy_identity(value: object) -> str:
    """Hash the historical, stable indented JSON identity claim."""

    return _digest((json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode())


def _compiler_seat(identity: str) -> str:
    """Derive the compiler-visible working-directory seat from carrier identity."""

    return f"d_{identity[:12]}"


def _carrier_identity(parameters: Mapping[str, object], generated: bytes) -> str:
    digest = _sha(
        parameters.get("generated_header_sha256"),
        "generated_header_sha256 must be a lowercase SHA-256",
    )
    _require(_digest(generated) == digest, "generated declarations differ from their pin")
    return digest


def _include_projection(parameters: Mapping[str, object]) -> DonorIncludeProjection:
    projection = parameters.get("include_projection")
    _require(
        projection is None or projection in _PROJECTIONS,
        "include_projection is outside the closed enum",
    )
    return DonorIncludeProjection(cast(str, projection or "none"))


def _validate_role_policy(parameters: Mapping[str, object]) -> None:
    if "role_policy" in parameters:
        _require(parameters["role_policy"] in _ROLE_POLICIES, "role_policy differs")


def _validated_overlay(
    intervention: ClassicRecipeIntervention,
    parameters: dict[str, JsonValue],
) -> DonorRecipeValidation:
    expected = {
        "canonical_overlay_replay",
        "compiler_state_carrier",
        "emission_policy",
        "include_projection",
        "rendering_identity_sha256",
        "renderings",
    }
    optional = {
        "canonical_overlay_replay",
        "compiler_state_carrier",
        "include_projection",
    }
    _exact_keys(parameters, expected, "donor source overlay", optional=optional)
    _require(
        parameters.get("emission_policy") == "donor_private_rendering_only",
        "donor source overlay emission policy differs",
    )
    replay = parameters.get("canonical_overlay_replay")
    _require(
        replay is None or replay == "owning_translation_unit_v1",
        "canonical overlay replay policy differs",
    )
    renderings = parameters.get("renderings")
    _require(
        isinstance(renderings, list) and bool(renderings),
        "renderings must be non-empty",
    )
    rendering_list = cast(list[JsonValue], renderings)
    paths: list[str] = []
    for index, raw in enumerate(rendering_list):
        _require(isinstance(raw, dict), f"renderings[{index}] must be an object")
        rendering = cast(dict[str, object], raw)
        _exact_keys(
            rendering,
            {"path", "operations", "clean_sha256", "rendered_sha256"},
            f"renderings[{index}]",
        )
        paths.append(_logical_path(rendering.get("path"), f"renderings[{index}].path"))
        _sha(rendering.get("clean_sha256"), f"renderings[{index}].clean_sha256 differs")
        _sha(rendering.get("rendered_sha256"), f"renderings[{index}].rendered_sha256 differs")
        operations = rendering.get("operations")
        _require(isinstance(operations, list), f"renderings[{index}].operations differs")
        _reject_payload_fields(operations, f"renderings[{index}].operations")
    _require(len(paths) == len(set(paths)), "donor rendering paths repeat")
    _require(
        len(paths) == len({path.casefold() for path in paths}),
        "donor rendering paths have a case-fold collision",
    )
    identity_claim: object = rendering_list
    if "compiler_state_carrier" in parameters or replay is not None:
        identity_claim = {"renderings": rendering_list}
        if "compiler_state_carrier" in parameters:
            cast(dict[str, object], identity_claim)["compiler_state_carrier"] = parameters[
                "compiler_state_carrier"
            ]
        if replay is not None:
            cast(dict[str, object], identity_claim)["canonical_overlay_replay"] = replay
    identity = _sha(
        parameters.get("rendering_identity_sha256"),
        "rendering_identity_sha256 must be a lowercase SHA-256",
    )
    _require(_legacy_identity(identity_claim) == identity, "rendering identity differs")
    force_payload: bytes | None = None
    carrier_identifiers = frozenset[str]()
    if "compiler_state_carrier" in parameters:
        _, force_payload, carrier_identifiers = _validate_overlay_carrier(
            parameters["compiler_state_carrier"]
        )
        _require(
            bool(carrier_identifiers),
            "compiler-state carrier has no declaration identifiers",
        )
    return DonorRecipeValidation(
        intervention.family,
        cast(Mapping[str, object], _freeze(parameters)),
        _compiler_seat(identity),
        _include_projection(parameters),
        None,
        force_payload,
        carrier_identifiers,
    )


def _validate_overlay_carrier(
    value: JsonValue,
) -> tuple[dict[str, JsonValue], bytes | None, frozenset[str]]:
    _require(isinstance(value, dict), "compiler_state_carrier must be an object")
    carrier = cast(dict[str, JsonValue], value)
    kind = carrier.get("kind")
    if kind in {"force_included_shape_v1", "force_included_pad_shape_v1"}:
        if kind == "force_included_shape_v1":
            names = ("classes", "functions")
            payload = generate_declaration_shape(
                _integer(carrier.get("classes"), "carrier.classes"),
                _integer(carrier.get("functions"), "carrier.functions"),
            )
        else:
            names = ("classes", "functions_per_class")
            payload = generate_pad_shape(
                _integer(carrier.get("classes"), "carrier.classes"),
                _integer(carrier.get("functions_per_class"), "carrier.functions_per_class"),
            )
        _exact_keys(
            carrier,
            {"kind", "placement", "generated_declarations_sha256", *names},
            "compiler_state_carrier",
        )
        _require(carrier.get("placement") == "force_include_v1", "carrier placement differs")
        _require(
            _digest(payload)
            == _sha(
                carrier.get("generated_declarations_sha256"),
                "carrier declarations digest differs",
            ),
            "carrier declarations differ from their pin",
        )
        return carrier, payload, _generated_identifiers(payload)
    _require(
        kind in {"extern_run_pair_v1", "declaration_run_triple_v1"},
        "compiler-state carrier kind differs",
    )
    roles = ("header", "seat") if kind == "extern_run_pair_v1" else ("pre", "post", "eof")
    placement = (
        "after_includes_and_eof_v1"
        if kind == "extern_run_pair_v1"
        else "start_after_includes_and_eof_v1"
    )
    expected = {"kind", "placement", "width", "generated_declarations_sha256"}
    expected.update(f"{role}_{field}" for role in roles for field in ("prefix", "count"))
    _exact_keys(carrier, expected, "compiler_state_carrier")
    _require(carrier.get("placement") == placement, "carrier placement differs")
    width = _integer(carrier.get("width"), "carrier.width", minimum=1, maximum=3)
    identities: set[str] = set()
    payloads: list[bytes] = []
    for role in roles:
        prefix = _identifier(carrier.get(f"{role}_prefix"), f"carrier.{role}_prefix")
        count = _integer(
            carrier.get(f"{role}_count"), f"carrier.{role}_count", minimum=1, maximum=999
        )
        payload = (
            generate_extern_run(prefix, count, width)
            if kind == "extern_run_pair_v1"
            else generate_forward_run(prefix, count, width)
        )
        generated_names = {f"{prefix}{index:0{width}d}" for index in range(count)}
        _require(
            identities.isdisjoint(generated_names),
            "carrier declaration identities collide",
        )
        identities.update(generated_names)
        payloads.append(payload)
    combined = b"".join(payloads)
    _require(
        _digest(combined)
        == _sha(
            carrier.get("generated_declarations_sha256"),
            "carrier declarations digest differs",
        ),
        "carrier declarations differ from their pin",
    )
    return carrier, None, frozenset(identities)


def validate_donor_recipe(
    intervention: ClassicRecipeIntervention,
    constraints: CandidateConstraints,
) -> DonorRecipeValidation:
    """Validate one donor declaration without reading or rendering source."""

    _require(intervention.role is ClassicRecipeRole.DONOR, "classic recipe is not a donor")
    _require(intervention.family in DONOR_FAMILIES, "classic recipe is not a donor family")
    _require(constraints.intervention_id == intervention.id, "constraints intervention differs")
    _require(constraints.family is intervention.family, "constraints family differs")
    _require(len(intervention.rationale) >= 32, "donor authenticity rationale is too weak")
    parameters = constraints.materialize()
    if intervention.family is ClassicRecipeFamily.DONOR_SOURCE_OVERLAY:
        return _validated_overlay(intervention, parameters)
    _require(
        parameters.get("emission_policy") == "non_emitting_declarations_only",
        "donor emission policy differs",
    )
    family = intervention.family
    generated: bytes
    force_payload: bytes | None = None
    common = {"emission_policy", "generated_header_sha256"}
    if family is ClassicRecipeFamily.DECLARATION_SHAPE:
        _exact_keys(
            parameters,
            common | {"classes", "functions", "role_policy"},
            family.value,
            optional={"role_policy"},
        )
        _validate_role_policy(parameters)
        generated = generate_declaration_shape(
            _integer(parameters.get("classes"), "classes"),
            _integer(parameters.get("functions"), "functions"),
        )
        force_payload = generated
    elif family is ClassicRecipeFamily.PAD_SHAPE:
        _exact_keys(
            parameters,
            common | {"classes", "functions_per_class", "donor_source"},
            family.value,
            optional={"donor_source"},
        )
        if "donor_source" in parameters:
            _logical_path(parameters["donor_source"], "donor_source")
        generated = generate_pad_shape(
            _integer(parameters.get("classes"), "classes"),
            _integer(parameters.get("functions_per_class"), "functions_per_class"),
        )
        force_payload = generated
    elif family is ClassicRecipeFamily.FORWARD_DECLARATION_RUN:
        _exact_keys(
            parameters,
            common | {"placement", "prefix", "count", "width"},
            family.value,
        )
        _require(
            parameters.get("placement") in {"prefix", "after_includes", "force_include", "suffix"},
            "forward-run placement differs",
        )
        generated = generate_forward_run(
            _identifier(parameters.get("prefix"), "prefix"),
            _integer(parameters.get("count"), "count"),
            _integer(parameters.get("width"), "width"),
        )
        if parameters["placement"] == "force_include":
            force_payload = generated
    elif family is ClassicRecipeFamily.EXTERN_RUN_PAIR:
        _exact_keys(
            parameters,
            common
            | {
                "header_prefix",
                "header_count",
                "seat_prefix",
                "seat_count",
                "width",
                "role_policy",
            },
            family.value,
            optional={"role_policy"},
        )
        _validate_role_policy(parameters)
        width = _integer(parameters.get("width"), "width", minimum=1, maximum=3)
        pieces: list[bytes] = []
        for seat in ("header", "seat"):
            count = _integer(parameters.get(f"{seat}_count"), f"{seat}_count", minimum=0)
            prefix = _identifier(parameters.get(f"{seat}_prefix"), f"{seat}_prefix")
            if count:
                pieces.append(generate_extern_run(prefix, count, width))
        _require(bool(pieces), "extern-run pair must contain a declaration")
        generated = b"".join(pieces)
    elif family is ClassicRecipeFamily.FORWARD_RUN_WITH_SHAPE:
        cross = {
            "donor_source",
            "donor_effective_source_sha256",
            "rendered_source_sha256",
            "rendered_source_size",
            "rendered_source_line_count",
            "role_policy",
        }
        _exact_keys(
            parameters,
            common | {"placement", "prefix", "count", "width", "classes", "functions"} | cross,
            family.value,
            optional=cross,
        )
        present = cross.intersection(parameters)
        _require(present in (set(), cross), "cross-TU carrier fields are incomplete")
        _require(parameters.get("placement") in {"prefix", "suffix"}, "placement differs")
        forward = generate_forward_run(
            _identifier(parameters.get("prefix"), "prefix"),
            _integer(parameters.get("count"), "count"),
            _integer(parameters.get("width"), "width"),
        )
        shape = generate_declaration_shape(
            _integer(parameters.get("classes"), "classes"),
            _integer(parameters.get("functions"), "functions"),
        )
        if present:
            _validate_role_policy(parameters)
            _logical_path(parameters["donor_source"], "donor_source")
            _sha(parameters["donor_effective_source_sha256"], "donor source digest differs")
            _sha(parameters["rendered_source_sha256"], "rendered source digest differs")
            _integer(parameters["rendered_source_size"], "rendered source size", minimum=1)
            _integer(
                parameters["rendered_source_line_count"],
                "rendered source line count",
                minimum=1,
            )
        generated = forward + shape
        force_payload = shape
    elif family is ClassicRecipeFamily.DECLARATION_RUN_TRIPLE:
        seats = {
            f"{seat}_{field}" for seat in ("pre", "post", "eof") for field in ("prefix", "count")
        }
        _exact_keys(
            parameters,
            common | {"width", "role_policy"} | seats,
            family.value,
            optional={"role_policy"},
        )
        _validate_role_policy(parameters)
        width = _integer(parameters.get("width"), "width", minimum=1, maximum=3)
        pieces = []
        used_prefixes: set[str] = set()
        for seat in ("pre", "post", "eof"):
            prefix = _identifier(parameters.get(f"{seat}_prefix"), f"{seat}_prefix")
            count = _integer(parameters.get(f"{seat}_count"), f"{seat}_count", minimum=0)
            if count:
                _require(prefix not in used_prefixes, "seated declaration stems repeat")
                used_prefixes.add(prefix)
                pieces.append(generate_forward_run(prefix, count, width))
        _require(bool(pieces), "declaration triple must contain a declaration")
        generated = b"".join(pieces)
    else:
        assert family is ClassicRecipeFamily.PREFIX_FORWARD_AFTER_INCLUDES_EXTERN
        _exact_keys(
            parameters,
            common
            | {
                "forward_prefix",
                "forward_count",
                "forward_width",
                "extern_prefix",
                "extern_count",
                "extern_width",
                "seat_proof",
                "rendered_source_sha256",
                "rendered_source_size",
                "rendered_source_line_count",
            },
            family.value,
        )
        forward = generate_forward_run(
            _identifier(parameters.get("forward_prefix"), "forward_prefix"),
            _integer(parameters.get("forward_count"), "forward_count"),
            _integer(parameters.get("forward_width"), "forward_width"),
        )
        extern = generate_extern_run(
            _identifier(parameters.get("extern_prefix"), "extern_prefix"),
            _integer(parameters.get("extern_count"), "extern_count"),
            _integer(parameters.get("extern_width"), "extern_width"),
        )
        _sha(parameters.get("rendered_source_sha256"), "rendered source digest differs")
        _integer(parameters.get("rendered_source_size"), "rendered source size", minimum=1)
        _integer(
            parameters.get("rendered_source_line_count"),
            "rendered source line count",
            minimum=1,
        )
        generated = forward + extern
    carrier_identity = _carrier_identity(parameters, generated)
    carrier_identifiers = _generated_identifiers(generated)
    _require(
        bool(carrier_identifiers),
        "generated declarations have no carrier identifiers",
    )
    return DonorRecipeValidation(
        family,
        cast(Mapping[str, object], _freeze(parameters)),
        _compiler_seat(carrier_identity),
        DonorIncludeProjection.NONE,
        generated,
        force_payload,
        carrier_identifiers,
    )


def _insert_after_includes(source: bytes, declarations: bytes, label: str) -> bytes:
    lines = source.split(b"\n")
    include_rows = [index for index, line in enumerate(lines) if line.startswith(b"#include")]
    _require(bool(include_rows), f"{label} source lacks an include seat")
    declarations_lines = declarations.rstrip(b"\n").split(b"\n")
    at = include_rows[-1] + 1
    return b"\n".join(lines[:at] + declarations_lines + lines[at:])


def _append_lines(source: bytes, declarations: bytes) -> bytes:
    return b"\n".join(source.split(b"\n") + declarations.rstrip(b"\n").split(b"\n"))


def _validate_special_seats(source: bytes, proof_value: object) -> None:
    _require(isinstance(proof_value, Mapping), "seat_proof must be an object")
    proof = cast(Mapping[str, object], proof_value)
    expected = {
        "kind",
        "prefix_offset",
        "prefix_input_sha256",
        "prefix_following_line_sha256",
        "prefix_context_sha256",
        "after_includes_offset",
        "preceding_line_sha256",
        "following_line_sha256",
        "centered_context_sha256",
    }
    _exact_keys(proof, expected, "seat_proof")
    _require(
        proof.get("kind") == "prefix_and_after_last_include_seats_v1",
        "seat kind differs",
    )
    _require(
        _integer(
            proof.get("prefix_offset"),
            "prefix_offset",
            minimum=0,
            maximum=0,
        )
        == 0,
        "prefix offset differs",
    )
    _require(
        _sha(proof.get("prefix_input_sha256"), "prefix input digest differs") == _digest(b""),
        "prefix input differs",
    )
    first_end = source.find(b"\n")
    _require(first_end >= 0 and len(source) >= 64, "source lacks a prefix witness")
    _require(
        _sha(proof.get("prefix_following_line_sha256"), "prefix line digest differs")
        == _digest(source[: first_end + 1])
        and _sha(proof.get("prefix_context_sha256"), "prefix context digest differs")
        == _digest(source[:64]),
        "prefix witness differs",
    )
    physical = source.splitlines(keepends=True)
    includes = [index for index, line in enumerate(physical) if line.startswith(b"#include")]
    _require(
        bool(includes) and includes[-1] + 1 < len(physical),
        "source lacks after-includes seat",
    )
    include_index = includes[-1]
    seat = sum(len(line) for line in physical[: include_index + 1])
    _require(
        _integer(
            proof.get("after_includes_offset"),
            "after_includes_offset",
            minimum=32,
            maximum=len(source) - 32,
        )
        == seat,
        "after-includes offset differs",
    )
    _require(
        _sha(proof.get("preceding_line_sha256"), "preceding line digest differs")
        == _digest(physical[include_index])
        and _sha(proof.get("following_line_sha256"), "following line digest differs")
        == _digest(physical[include_index + 1])
        and _sha(proof.get("centered_context_sha256"), "seat context digest differs")
        == _digest(source[seat - 32 : seat + 32]),
        "after-includes witness differs",
    )


def _render_overlay_carrier(source: bytes, carrier: Mapping[str, object]) -> bytes:
    kind = carrier["kind"]
    if kind in {"force_included_shape_v1", "force_included_pad_shape_v1"}:
        return source
    if kind == "extern_run_pair_v1":
        header = generate_extern_run(
            cast(str, carrier["header_prefix"]),
            cast(int, carrier["header_count"]),
            cast(int, carrier["width"]),
        )
        seat = generate_extern_run(
            cast(str, carrier["seat_prefix"]),
            cast(int, carrier["seat_count"]),
            cast(int, carrier["width"]),
        )
        return _append_lines(_insert_after_includes(source, header, "overlay carrier"), seat)
    assert kind == "declaration_run_triple_v1"
    runs = {
        name: generate_forward_run(
            cast(str, carrier[f"{name}_prefix"]),
            cast(int, carrier[f"{name}_count"]),
            cast(int, carrier["width"]),
        )
        for name in ("pre", "post", "eof")
    }
    return _append_lines(
        runs["pre"] + _insert_after_includes(source, runs["post"], "overlay carrier"),
        runs["eof"],
    )


def _source_identifiers(source: bytes) -> frozenset[str]:
    return frozenset(
        match.group().decode("ascii") for match in re.finditer(rb"[A-Za-z_][A-Za-z0-9_]*", source)
    )


def _generated_identifiers(generated: bytes) -> frozenset[str]:
    return frozenset(
        match.group(1).decode("ascii")
        for match in re.finditer(
            rb"(?:\bclass\s+|\bextern\s+int\s+|\bvoid\s+)([A-Za-z_][A-Za-z0-9_]*)",
            generated,
        )
    )


def _render_ordinary_source(
    validation: DonorRecipeValidation,
    source: bytes,
) -> bytes:
    parameters = validation.parameters
    generated = validation.generated_declarations
    assert generated is not None
    family = validation.family
    if family in {ClassicRecipeFamily.DECLARATION_SHAPE, ClassicRecipeFamily.PAD_SHAPE}:
        return source
    if family is ClassicRecipeFamily.FORWARD_DECLARATION_RUN:
        placement = parameters["placement"]
        if placement == "prefix":
            return generated + source
        if placement == "suffix":
            return _append_lines(source, generated)
        if placement == "after_includes":
            return _insert_after_includes(source, generated, family.value)
        assert placement == "force_include"
        return source
    if family is ClassicRecipeFamily.EXTERN_RUN_PAIR:
        width = cast(int, parameters["width"])
        header = (
            generate_extern_run(
                cast(str, parameters["header_prefix"]),
                cast(int, parameters["header_count"]),
                width,
            )
            if parameters["header_count"]
            else b""
        )
        seat = (
            generate_extern_run(
                cast(str, parameters["seat_prefix"]),
                cast(int, parameters["seat_count"]),
                width,
            )
            if parameters["seat_count"]
            else b""
        )
        rendered = _insert_after_includes(source, header, family.value) if header else source
        return _append_lines(rendered, seat) if seat else rendered
    if family is ClassicRecipeFamily.FORWARD_RUN_WITH_SHAPE:
        forward = generate_forward_run(
            cast(str, parameters["prefix"]),
            cast(int, parameters["count"]),
            cast(int, parameters["width"]),
        )
        if parameters["placement"] == "prefix":
            return forward + source
        return _append_lines(source, forward)
    if family is ClassicRecipeFamily.DECLARATION_RUN_TRIPLE:
        width = cast(int, parameters["width"])
        runs = {
            seat: (
                generate_forward_run(
                    cast(str, parameters[f"{seat}_prefix"]),
                    cast(int, parameters[f"{seat}_count"]),
                    width,
                )
                if parameters[f"{seat}_count"]
                else b""
            )
            for seat in ("pre", "post", "eof")
        }
        rendered = runs["pre"] + source
        if runs["post"]:
            rendered = runs["pre"] + _insert_after_includes(source, runs["post"], family.value)
        return _append_lines(rendered, runs["eof"]) if runs["eof"] else rendered
    assert family is ClassicRecipeFamily.PREFIX_FORWARD_AFTER_INCLUDES_EXTERN
    _validate_special_seats(source, parameters["seat_proof"])
    forward = generate_forward_run(
        cast(str, parameters["forward_prefix"]),
        cast(int, parameters["forward_count"]),
        cast(int, parameters["forward_width"]),
    )
    extern = generate_extern_run(
        cast(str, parameters["extern_prefix"]),
        cast(int, parameters["extern_count"]),
        cast(int, parameters["extern_width"]),
    )
    return forward + _insert_after_includes(source, extern, family.value)


def _overlay_files(
    outputs: Mapping[str, bytes],
    primary: str,
    projection: DonorIncludeProjection,
) -> tuple[dict[str, bytes], tuple[str, ...]]:
    files = {"s.cpp": outputs[primary]}
    include_directories: list[str] = ["inc"]
    non_primary = [(path, data) for path, data in outputs.items() if path != primary]
    if projection is not DonorIncludeProjection.SOURCE_ROOT_MIRROR_ONLY:
        basenames: set[str] = set()
        for path, data in non_primary:
            name = PurePosixPath(path).name
            folded = name.casefold()
            _require(folded not in basenames, "flat donor include projection collides")
            basenames.add(folded)
            files[f"inc/{name}"] = data
    if projection is not DonorIncludeProjection.NONE:
        # The primary is compiled from relative ``s.cpp``.  Its private mirror
        # deliberately remains the effective source, exactly as in the proven
        # legacy lane; only rendered secondary paths override that mirror.
        for path, data in non_primary:
            files[f"inc/source/{path}"] = data
        parent = PurePosixPath(primary).parent.as_posix()
        include_directories.append("inc/source" if parent == "." else f"inc/source/{parent}")
    return files, tuple(include_directories)


def _freeze_bytes(value: Mapping[str, bytes]) -> Mapping[str, bytes]:
    keys = list(value)
    _require(len(keys) == len(set(keys)), "staged donor file paths repeat")
    _require(
        len(keys) == len({key.casefold() for key in keys}),
        "staged donor file paths have a case-fold collision",
    )
    for key in keys:
        _logical_path(key, "staged donor path")
    return MappingProxyType(dict(value))


def prepare_donor_compile_request(
    intervention: ClassicRecipeIntervention,
    *,
    source_path: str,
    clean_source: bytes,
    effective_source: bytes,
    receipts: Iterable[ClassicProofReceipt],
    clean_sources: Mapping[str, bytes] | None = None,
    canonical_overlay_operations: Sequence[Mapping[str, object]] | None = None,
) -> DonorCompileRequest:
    """Render one closed donor request entirely from authenticated input bytes."""

    source_path = _logical_path(source_path, "donor source")
    _require(isinstance(clean_source, bytes), "clean source must be immutable bytes")
    _require(isinstance(effective_source, bytes), "effective source must be immutable bytes")
    constraints = matching_candidate_constraints(intervention, receipts)
    validation = validate_donor_recipe(intervention, constraints)
    parameters = validation.parameters
    input_digests: dict[str, str] = {
        f"clean:{source_path}": _digest(clean_source),
        f"effective:{source_path}": _digest(effective_source),
    }
    logical_outputs: dict[str, bytes]
    files: dict[str, bytes]
    overlay_receipts: tuple[ClassicOverlayOutputReceipt, ...] = ()
    include_directories: tuple[str, ...] = ()
    rendering_material: dict[str, JsonValue]
    if intervention.family is ClassicRecipeFamily.DONOR_SOURCE_OVERLAY:
        supplied = dict(clean_sources or {})
        supplied.setdefault(source_path, clean_source)
        normalized_inputs: dict[str, bytes] = {}
        for raw_path, data in supplied.items():
            path = _logical_path(raw_path, "overlay input path")
            _require(isinstance(data, bytes), f"overlay input {path!r} is not immutable bytes")
            _require(
                path.casefold() not in {key.casefold() for key in normalized_inputs},
                "overlay input paths case-fold collide",
            )
            normalized_inputs[path] = data
            input_digests[f"clean:{path}"] = _digest(data)
        raw_renderings = parameters["renderings"]
        assert isinstance(raw_renderings, tuple)
        declarations: list[dict[str, object]] = []
        replay = parameters.get("canonical_overlay_replay")
        if replay is not None:
            _require(
                canonical_overlay_operations is not None,
                "canonical overlay replay operations are required",
            )
        else:
            _require(
                canonical_overlay_operations is None,
                "canonical overlay operations were supplied without a replay declaration",
            )
        for index, raw in enumerate(raw_renderings):
            _require(isinstance(raw, Mapping), f"renderings[{index}] differs")
            path = cast(str, raw["path"])
            _require(path in normalized_inputs, f"overlay clean input is absent: {path}")
            _require(
                _digest(normalized_inputs[path]) == raw["clean_sha256"],
                f"overlay clean input differs: {path}",
            )
            operations = [
                cast(dict[str, object], _thaw(item))
                for item in cast(tuple[object, ...], raw["operations"])
            ]
            if index == 0 and canonical_overlay_operations is not None:
                replay_ops = [deepcopy(dict(item)) for item in canonical_overlay_operations]
                _reject_payload_fields(replay_ops, "canonical overlay operations")
                operations = replay_ops + operations
            declarations.append(
                {
                    "path": path,
                    "clean": raw["clean_sha256"],
                    "effective": raw["rendered_sha256"],
                    "ops": operations,
                }
            )
        try:
            from reprobit.classic_overlay_document import render_classic_overlay_declarations
        except ImportError as exc:  # pragma: no cover - only during partial installations
            raise DonorSourceError("classic overlay renderer is unavailable") from exc
        result = render_classic_overlay_declarations(declarations, normalized_inputs)
        logical_outputs = dict(result.outputs)
        overlay_receipts = result.receipts
        _require(source_path in logical_outputs, "donor overlay does not render its source")
        carrier_value = parameters.get("compiler_state_carrier")
        if carrier_value is not None:
            _require(len(logical_outputs) == 1, "compiler-state carrier requires one rendering")
            assert isinstance(carrier_value, Mapping)
            logical_outputs[source_path] = _render_overlay_carrier(
                logical_outputs[source_path], carrier_value
            )
        files, include_directories = _overlay_files(
            logical_outputs, source_path, validation.include_projection
        )
        rendering_material = {
            "kind": "donor_source_overlay_v1",
            "outputs": {path: _digest(data) for path, data in sorted(logical_outputs.items())},
            "canonical_replay_digest": (
                _digest(canonical_json(list(canonical_overlay_operations)))
                if canonical_overlay_operations is not None
                else None
            ),
        }
    else:
        donor_source = parameters.get("donor_source")
        if donor_source is not None:
            _require(source_path == donor_source, "request source differs from donor_source")
        expected_input = parameters.get("donor_effective_source_sha256")
        if expected_input is not None:
            _require(_digest(effective_source) == expected_input, "donor effective source differs")
        generated = validation.generated_declarations
        assert generated is not None
        if intervention.family is ClassicRecipeFamily.PREFIX_FORWARD_AFTER_INCLUDES_EXTERN:
            overlap = _source_identifiers(effective_source).intersection(
                _generated_identifiers(generated)
            )
            _require(
                not overlap,
                f"generated declaration identifiers collide: {sorted(overlap)[:4]}",
            )
        rendered = _render_ordinary_source(validation, effective_source)
        expected_output = parameters.get("rendered_source_sha256")
        if expected_output is not None:
            _require(
                _digest(rendered) == expected_output
                and len(rendered) == parameters["rendered_source_size"]
                and rendered.count(b"\n") == parameters["rendered_source_line_count"],
                "rendered donor source differs from its pins",
            )
        logical_outputs = {source_path: rendered}
        files = {"s.cpp": rendered}
        rendering_material = {
            "kind": "declaration_carrier_v1",
            "source": source_path,
            "generated_declarations": _digest(generated),
            "rendered_source": _digest(rendered),
        }
    force_includes: tuple[str, ...] = ()
    if validation.force_include_payload is not None:
        files["run.h"] = validation.force_include_payload
        force_includes = ("run.h",)
    compiler_additions = DonorCompilerAdditions(
        force_includes=force_includes,
        include_directories=include_directories,
        include_projection=validation.include_projection,
    )
    carrier_identifiers = validation.carrier_identifiers
    additions_material = {
        "build_target": intervention.build_target,
        "compiler_seat": validation.compiler_seat,
        "force_includes": list(compiler_additions.force_includes),
        "include_directories": list(compiler_additions.include_directories),
        "include_projection": compiler_additions.include_projection.value,
    }
    frozen_files = _freeze_bytes(files)
    frozen_outputs = _freeze_bytes(logical_outputs)
    output_digests = {path: _digest(data) for path, data in sorted(files.items())}
    receipt = DonorCompileReceipt(
        intervention.id,
        intervention.family,
        constraints.digest,
        MappingProxyType(dict(sorted(input_digests.items()))),
        MappingProxyType(output_digests),
        Digest.from_bytes(canonical_json(additions_material)),
        Digest.from_bytes(canonical_json(rendering_material)),
    )
    return DonorCompileRequest(
        intervention.id,
        validation.compiler_seat,
        intervention.family,
        intervention.build_target,
        source_path,
        "s.cpp",
        frozen_files,
        frozen_outputs,
        compiler_additions,
        carrier_identifiers,
        receipt,
        overlay_receipts,
    )


__all__ = [
    "DONOR_FAMILIES",
    "CandidateConstraints",
    "DonorCompileReceipt",
    "DonorCompileRequest",
    "DonorCompilerAdditions",
    "DonorIncludeProjection",
    "DonorRecipeValidation",
    "DonorSourceError",
    "donor_requires_dependency_tracking",
    "generate_declaration_shape",
    "generate_extern_run",
    "generate_forward_run",
    "generate_pad_shape",
    "matching_candidate_constraints",
    "merge_candidate_constraints",
    "prepare_donor_compile_request",
    "validate_donor_recipe",
]
