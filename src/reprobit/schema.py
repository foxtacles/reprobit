"""Schema-v3 project models and generated schema documents."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from itertools import pairwise
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal, Self, TypeAlias

from pydantic import (
    ConfigDict,
    Field,
    TypeAdapter,
    WithJsonSchema,
    field_validator,
    model_validator,
)
from pydantic import JsonValue as PydanticJsonValue

from reprobit.model import (
    AuthenticityPolicy,
    BuildTarget,
    ByteRange,
    Digest,
    Identifier,
    Scope,
    Sha256Hex,
    StrictModel,
)
from reprobit.paths import PathContractError, normalize_logical_path
from reprobit.producer_graph import (
    ProducerGraphDocument,
    linker_library_sequence,
    producer_graph_accepts_source,
    toolchain_document_digest,
)
from reprobit.strict_json import JsonValue, canonical_json

RelativePath = Annotated[str, Field(min_length=1, max_length=4096)]
NativeJsonValue: TypeAlias = Annotated[
    PydanticJsonValue,
    WithJsonSchema({"type": ["array", "boolean", "integer", "null", "number", "object", "string"]}),
]


class SchemaError(ValueError):
    """Raised when a project tree is unsafe or internally inconsistent."""


class SchemaVersionError(SchemaError):
    """Raised when a document is not schema v3."""


def _check_relative_path(value: str) -> str:
    if "\x00" in value:
        raise ValueError("path contains NUL")
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) >= 2 and normalized[1] == ":"):
        raise ValueError("committed paths must be project-relative")
    if any(part in {"", ".", ".."} for part in normalized.split("/")):
        raise ValueError("path must be normalized and remain within the project")
    return normalized


class CommandSpec(StrictModel):
    """A declarative command with no shell expansion."""

    argv: Annotated[tuple[str, ...], Field(min_length=1)]
    cwd: RelativePath = "."
    timeout_seconds: Annotated[int, Field(ge=1, le=86_400)] = 900

    @field_validator("cwd")
    @classmethod
    def validate_cwd(cls, value: str) -> str:
        if value == ".":
            return value
        return _check_relative_path(value)

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item or "\x00" in item for item in value):
            raise ValueError("argv entries must be non-empty and contain no NUL")
        return value


class ProducerGraphBuildAdapter(StrictModel):
    """Certification runtime driven exclusively by committed producer nodes."""

    kind: Literal["producer-graph"] = "producer-graph"


class CommandBuildAdapter(StrictModel):
    kind: Literal["command"] = "command"
    configure: tuple[CommandSpec, ...] = ()
    build: Annotated[tuple[CommandSpec, ...], Field(min_length=1)]


class ToolchainRef(StrictModel):
    adapter: Literal["classic-msvc"] = "classic-msvc"
    profile: Identifier
    lock_file: RelativePath = "reprobit/toolchain.lock.json"

    @field_validator("lock_file")
    @classmethod
    def validate_lock_file(cls, value: str) -> str:
        return _check_relative_path(value)


class LogicalPathProfile(StrictModel):
    id: Identifier = "dos-stable-v1"
    source: Annotated[str, Field(pattern=r"^[A-Za-z]:[\\/].+")]
    build: Annotated[str, Field(pattern=r"^[A-Za-z]:[\\/].+")]
    toolchain: Annotated[str, Field(pattern=r"^[A-Za-z]:[\\/].+")]

    @field_validator("source", "build", "toolchain")
    @classmethod
    def canonical_logical_root(cls, value: str) -> str:
        try:
            return normalize_logical_path(value)
        except PathContractError as exc:
            raise ValueError(str(exc)) from exc

    @model_validator(mode="after")
    def roots_do_not_overlap(self) -> LogicalPathProfile:
        roots = (self.source, self.build, self.toolchain)
        if len({value[:2].casefold() for value in roots}) != 1:
            raise ValueError("logical source, build, and toolchain roots must share one drive")
        normalized = tuple(value.replace("/", "\\").rstrip("\\").casefold() for value in roots)
        for index, left in enumerate(normalized):
            for right in normalized[index + 1 :]:
                if left == right or left.startswith(right + "\\") or right.startswith(left + "\\"):
                    raise ValueError("logical source, build, and toolchain roots must not overlap")
        components = tuple(root[3:].split("\\") for root in roots)
        for index, left_components in enumerate(components):
            for right_components in components[index + 1 :]:
                for left_component, right_component in zip(
                    left_components, right_components, strict=False
                ):
                    if left_component.casefold() != right_component.casefold():
                        break
                    if left_component != right_component:
                        raise ValueError(
                            "logical source, build, and toolchain roots must spell shared "
                            "DOS path components identically"
                        )
        return self


class LiteralVerifier(StrictModel):
    kind: Literal["literal"] = "literal"


VerifierSpec: TypeAlias = LiteralVerifier


class LegacyAllowlistEntry(StrictModel):
    """Project-level pin for one finite legacy oracle installation."""

    intervention_id: Identifier
    allowlist_digest: Digest
    proof_receipt_digest: Digest
    range_count: Annotated[int, Field(gt=0)]
    byte_count: Annotated[int, Field(gt=0)]
    maximum_oracle_payload_bytes: Annotated[int, Field(gt=0)]


class AuthenticitySettings(StrictModel):
    policy: AuthenticityPolicy = AuthenticityPolicy.CLEAN
    legacy_allowlist: tuple[LegacyAllowlistEntry, ...] = ()

    @model_validator(mode="after")
    def validate_allowlist(self) -> AuthenticitySettings:
        ids = [item.intervention_id for item in self.legacy_allowlist]
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            raise ValueError("legacy allowlist must be unique and canonically ordered")
        if self.policy is AuthenticityPolicy.CLEAN and self.legacy_allowlist:
            raise ValueError("clean authenticity policy cannot contain a legacy allowlist")
        return self


class TargetSpec(StrictModel):
    id: Identifier
    artifact: RelativePath
    oracle: RelativePath

    @field_validator("artifact", "oracle")
    @classmethod
    def validate_paths(cls, value: str) -> str:
        return _check_relative_path(value)


class ManifestLayout(StrictModel):
    source_manifest: RelativePath = "reprobit/source-manifest.json"
    build_plan: RelativePath = "reprobit/build-plan.json"
    producer_graph: RelativePath = "reprobit/producer-graph.json"
    interventions: RelativePath = "reprobit/interventions"
    proofs: RelativePath = "reprobit/proofs"
    oracles: RelativePath = "reprobit/oracles"

    @field_validator(
        "source_manifest",
        "build_plan",
        "producer_graph",
        "interventions",
        "proofs",
        "oracles",
    )
    @classmethod
    def validate_paths(cls, value: str) -> str:
        return _check_relative_path(value)


class ProjectSpec(StrictModel):
    """The small, human-edited schema-v3 project entry point."""

    schema_version: Literal[3]
    project_id: Identifier
    state_dir: RelativePath = ".reprobit-state"
    build: Annotated[
        ProducerGraphBuildAdapter | CommandBuildAdapter,
        Field(discriminator="kind"),
    ]
    toolchain: ToolchainRef
    paths: LogicalPathProfile
    verifier: VerifierSpec = Field(default_factory=LiteralVerifier)
    authenticity: AuthenticitySettings = Field(default_factory=AuthenticitySettings)
    layout: ManifestLayout = Field(default_factory=ManifestLayout)
    targets: Annotated[tuple[TargetSpec, ...], Field(min_length=1)]

    @field_validator("state_dir")
    @classmethod
    def validate_state_dir(cls, value: str) -> str:
        return _check_relative_path(value)

    @model_validator(mode="after")
    def target_ids_are_unique(self) -> ProjectSpec:
        _require_unique((target.id for target in self.targets), "target id")
        resolved_paths = [
            (kind, target.id, value.replace("\\", "/").casefold())
            for target in self.targets
            for kind, value in (("artifact", target.artifact), ("oracle", target.oracle))
        ]
        owners: dict[str, tuple[str, str]] = {}
        for kind, target_id, path in resolved_paths:
            if previous := owners.get(path):
                raise ValueError(
                    "target artifact/oracle paths must be unique; "
                    f"{previous[0]} for {previous[1]!r} and {kind} for {target_id!r} "
                    "resolve to the same path"
                )
            owners[path] = (kind, target_id)
        return self


class MsvcRelease(StrEnum):
    V4_2 = "4.2"
    V5_RTM = "5.0-rtm"
    V5_SP1 = "5.0-sp1"
    V5_SP2 = "5.0-sp2"
    V5_SP3 = "5.0-sp3"


class LockedTool(StrictModel):
    id: Identifier
    path: RelativePath
    digest: Digest
    size: Annotated[int, Field(gt=0)] | None = None
    roles: tuple[Identifier, ...] = ()

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _check_relative_path(value)


class InputTreeReceipt(StrictModel):
    id: Identifier
    path: RelativePath
    algorithm: Literal["portable-tree-v1"] = "portable-tree-v1"
    entry_count: Annotated[int, Field(ge=0)]
    max_depth: Annotated[int, Field(ge=0)]
    membership_digest: Digest
    content_digest: Digest

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _check_relative_path(value)


class ToolchainProfileSource(StrictModel):
    """An immutable repository input mapped to installed profile paths.

    File and tree receipts remain the content authority.  This compact mapping
    freezes reviewed repository inputs associated with the selected profile;
    it does not assert or prove how the installed bytes were acquired.
    """

    repository: Annotated[str, Field(min_length=1, max_length=2048)]
    revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    paths: Annotated[tuple[RelativePath, ...], Field(min_length=1)]

    @field_validator("repository")
    @classmethod
    def validate_repository(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 0x20 for character in value):
            raise ValueError("toolchain profile-source repository must be a canonical URL")
        return value

    @field_validator("paths")
    @classmethod
    def validate_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        checked = tuple(_check_relative_path(path) for path in value)
        ordered = tuple(sorted(checked, key=str.casefold))
        if checked != ordered:
            raise ValueError("toolchain profile-source paths must be canonically ordered")
        if len({path.casefold() for path in checked}) != len(checked):
            raise ValueError("toolchain profile-source paths collide under DOS case folding")
        return checked


class SourceManifestEntry(StrictModel):
    """One portable, regular project input in the clean source baseline."""

    path: RelativePath
    size: Annotated[int, Field(ge=0)]
    digest: Digest

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        checked = _check_relative_path(value)
        if "\\" in checked or PurePosixPath(checked).as_posix() != checked:
            raise ValueError("source manifest paths must be canonical POSIX paths")
        return checked


class SourceManifestDocument(StrictModel):
    """Complete clean-source authority, separate from effective overlays and provenance."""

    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"complete": {"const": True}},
                        "required": ["complete"],
                    },
                    "then": {"properties": {"entries": {"minItems": 1}}},
                }
            ]
        }
    )

    schema_version: Literal[3]
    algorithm: Literal["portable-source-v1"] = "portable-source-v1"
    complete: bool
    entries: tuple[SourceManifestEntry, ...]

    @model_validator(mode="after")
    def entries_are_canonical(self) -> SourceManifestDocument:
        if self.complete and not self.entries:
            raise ValueError("complete source manifest requires at least one entry")
        ordered = sorted(self.entries, key=lambda item: (item.path.casefold(), item.path))
        if list(self.entries) != ordered:
            raise ValueError("source manifest entries must be canonically ordered")
        folded = [item.path.casefold() for item in self.entries]
        if len(folded) != len(set(folded)):
            raise ValueError("source manifest paths collide under DOS case folding")
        return self


def source_manifest_digest(document: SourceManifestDocument) -> Digest:
    """Digest the complete canonical wire document (without a self-reference)."""

    return Digest.from_bytes(canonical_json(document.model_dump(mode="json")))


class ToolchainLock(StrictModel):
    schema_version: Literal[3]
    profile: Identifier
    adapter: Literal["classic-msvc"] = "classic-msvc"
    release: MsvcRelease
    profile_sources: tuple[ToolchainProfileSource, ...] = ()
    tools: Annotated[tuple[LockedTool, ...], Field(min_length=1)]
    runtime_files: tuple[LockedTool, ...] = ()
    input_trees: tuple[InputTreeReceipt, ...] = ()

    @model_validator(mode="after")
    def tool_ids_are_unique(self) -> ToolchainLock:
        _require_unique(
            (tool.id for tool in (*self.tools, *self.runtime_files)),
            "locked tool id",
        )
        _require_unique((tree.id for tree in self.input_trees), "input tree id")
        locked_paths = [item.path for item in self.tools]
        locked_paths.extend(item.path for item in self.runtime_files)
        locked_paths.extend(item.path for item in self.input_trees)
        folded_paths = [path.casefold() for path in locked_paths]
        if len(folded_paths) != len(set(folded_paths)):
            raise ValueError("locked toolchain paths collide under DOS case folding")
        source_keys = [(source.repository, source.revision) for source in self.profile_sources]
        if len(source_keys) != len(set(source_keys)):
            raise ValueError("toolchain profile-source repository revision is repeated")
        source_paths = [path for source in self.profile_sources for path in source.paths]
        folded_source_paths = [path.casefold() for path in source_paths]
        if len(folded_source_paths) != len(set(folded_source_paths)):
            raise ValueError("toolchain profile-source path is assigned more than once")
        unknown_paths = set(folded_source_paths) - set(folded_paths)
        if unknown_paths:
            raise ValueError(
                f"toolchain profile-source mapping names unlocked paths: {sorted(unknown_paths)}"
            )
        return self


class InterventionBase(StrictModel):
    id: Identifier
    version: Literal[1] = 1
    scope: Scope
    rationale: Annotated[str, Field(min_length=1, max_length=4096)]
    dependencies: tuple[Identifier, ...] = ()
    beneficiaries: tuple[Scope, ...] = ()

    @model_validator(mode="after")
    def no_self_dependency(self) -> InterventionBase:
        if self.id in self.dependencies:
            raise ValueError("intervention cannot depend on itself")
        if self.scope.function is not None and self.beneficiaries:
            raise ValueError("function-scoped intervention cannot declare shared beneficiaries")
        beneficiary_keys: list[tuple[str, str, str]] = []
        for beneficiary in self.beneficiaries:
            if beneficiary.function is None or beneficiary.translation_unit is None:
                raise ValueError("cost beneficiaries must name a function scope")
            if beneficiary.target != self.scope.target:
                raise ValueError("cost beneficiaries must remain within the intervention target")
            if (
                self.scope.translation_unit is not None
                and beneficiary.translation_unit != self.scope.translation_unit
            ):
                raise ValueError(
                    "translation-unit intervention beneficiaries must remain within that unit"
                )
            beneficiary_keys.append(
                (beneficiary.target, beneficiary.translation_unit, beneficiary.function)
            )
        if beneficiary_keys != sorted(beneficiary_keys) or len(beneficiary_keys) != len(
            set(beneficiary_keys)
        ):
            raise ValueError("cost beneficiaries must be unique and canonically ordered")
        return self


class StateCarrierIntervention(InterventionBase):
    kind: Literal["state_carrier"] = "state_carrier"
    carrier: Identifier


class GeneratedSupplierIntervention(InterventionBase):
    kind: Literal["generated_supplier"] = "generated_supplier"
    supplier: Identifier


class MetadataNormalizationIntervention(InterventionBase):
    kind: Literal["metadata_normalization"] = "metadata_normalization"
    field: Identifier
    value: int | str


class LinkOrderingIntervention(InterventionBase):
    kind: Literal["link_ordering"] = "link_ordering"
    item_ids: Annotated[tuple[Identifier, ...], Field(min_length=2)]


class EqualBodyDonorIntervention(InterventionBase):
    kind: Literal["equal_body_donor"] = "equal_body_donor"
    donor_artifact: Identifier
    donor_symbol: Annotated[str, Field(min_length=1, max_length=2048)]
    expected_size: Annotated[int, Field(gt=0)]


class StructuralMode(StrEnum):
    RESIZE = "resize"
    EXCEPTION_HANDLING = "exception_handling"
    RELOCATION_LAYOUT = "relocation_layout"
    COMPLETE_TARGET = "complete_target"


class StructuralDonorIntervention(InterventionBase):
    kind: Literal["structural_donor"] = "structural_donor"
    mode: StructuralMode
    donor_artifact: Identifier
    donor_symbol: Annotated[str, Field(min_length=1, max_length=2048)]


class CrossTuDonorIntervention(InterventionBase):
    kind: Literal["cross_tu_donor"] = "cross_tu_donor"
    donor_translation_unit: Identifier
    donor_artifact: Identifier
    donor_symbol: Annotated[str, Field(min_length=1, max_length=2048)]


class SemanticRewriteMethod(StrEnum):
    REGISTER_BIJECTION = "register_bijection"
    SCHEDULING = "scheduling"
    INSTRUCTION_FORM = "instruction_form"
    WEB_RECOLOUR = "web_recolour"
    FLOATING_POINT = "floating_point"
    DONOR_REWRITE = "donor_rewrite"


class SemanticRewriteIntervention(InterventionBase):
    kind: Literal["semantic_rewrite"] = "semantic_rewrite"
    method: SemanticRewriteMethod
    source_artifact: Identifier
    rewrite_digest: Digest


class BinarySurgeryMethod(StrEnum):
    INSTRUCTION_MOSAIC = "instruction_mosaic"
    INSTRUCTION_HYBRID = "instruction_hybrid"
    TEXT_REPACK = "text_repack"
    DATA_REPACK = "data_repack"


class BinarySurgeryIntervention(InterventionBase):
    kind: Literal["binary_surgery"] = "binary_surgery"
    method: BinarySurgeryMethod
    source_artifacts: Annotated[tuple[Identifier, ...], Field(min_length=1)]
    output_digest: Digest


class ClassicRecipeFamily(StrEnum):
    """Closed classic recipe families supported by the current proof model.

    ``source_overlay_graph`` is project-level authority: after its closed typed-source
    proof and any exact sparse declaration-counterfactual compiler audits, rendered
    bytes may enter the primary compiler seat with origin
    ``certified-project-overlay``.
    ``donor_source_overlay`` remains donor-private and cannot enter a primary project
    compiler seat.
    """

    DECLARATION_SHAPE = "declaration_shape"
    DONOR_SOURCE_OVERLAY = "donor_source_overlay"
    FORWARD_DECLARATION_RUN = "forward_declaration_run"
    PAD_SHAPE = "pad_shape"
    EXTERN_RUN_PAIR = "extern_run_pair"
    FORWARD_RUN_WITH_SHAPE = "forward_run_with_shape"
    DECLARATION_RUN_TRIPLE = "declaration_run_triple"
    PREFIX_FORWARD_AFTER_INCLUDES_EXTERN = "prefix_forward_after_includes_extern"
    EQUAL_BODY_STRICT = "equal_body_strict"
    EQUAL_BODY_EH_STRUCTURAL_LOCAL = "equal_body_eh_structural_local"
    SAME_SLOT_RESIZE = "same_slot_resize"
    EQUAL_BODY_EH_RELOC_LAYOUT = "equal_body_eh_reloc_layout"
    RETAIL_EXACT_RELOC_DIVERGENT = "retail_exact_reloc_divergent"
    RETAIL_EXACT_DONOR_REWRITING = "retail_exact_donor_rewriting"
    RETAIL_EXACT_INSTRUCTION_MOSAIC = "retail_exact_instruction_mosaic"
    RETAIL_EXACT_REGISTER_BIJECTION = "retail_exact_register_bijection"
    RETAIL_EXACT_SOURCE_EQUAL_BODY = "retail_exact_source_equal_body"
    RETAIL_EXACT_COMPOSED_REWRITING = "retail_exact_composed_rewriting"
    RETAIL_EXACT_SOURCE_TARGET_CLOSURE = "retail_exact_source_target_closure"
    RETAIL_EXACT_WEB_RECOLOUR = "retail_exact_web_recolour"
    RETAIL_EXACT_CROSS_TU_COMPLETE_TARGET_RESIZE = "retail_exact_cross_tu_complete_target_resize"
    RETAIL_EXACT_REGISTER_BIJECTION_REENCODING = "retail_exact_register_bijection_reencoding"
    RETAIL_EXACT_SAME_TU_INSTRUCTION_HYBRID_RESIZE = (
        "retail_exact_same_tu_instruction_hybrid_resize"
    )
    RETAIL_EXACT_SIMULATED_ELISION = "retail_exact_simulated_elision"
    SOURCE_OVERLAY_GRAPH = "source_overlay_graph"
    ARCHIVE_ADMISSION = "archive_admission"
    IMAGE_METADATA = "image_metadata"
    IMAGE_LINK_ORDER = "image_link_order"
    IMAGE_BINARY_REPACK = "image_binary_repack"


class ClassicRecipeRole(StrEnum):
    FUNCTION = "function"
    DONOR = "donor"
    PROJECT = "project"


_FORBIDDEN_CLASSIC_FIELDS = frozenset(
    {
        "bytes",
        "payload",
        "oracle_path",
        "reference_path",
        "callable",
        "script",
        "python",
        "template",
    }
)


class ClassicField(StrictModel):
    """One canonically ordered field containing strict native JSON."""

    name: Annotated[str, Field(min_length=1, max_length=128)]
    value: NativeJsonValue

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("classic field name contains NUL")
        return value


def _forbidden_classic_paths(fields: tuple[ClassicField, ...]) -> tuple[str, ...]:
    found: list[str] = []

    def visit(value: NativeJsonValue, prefix: str) -> None:
        if isinstance(value, dict):
            for name, child in value.items():
                path = f"{prefix}.{name}" if prefix else name
                normalized = name.casefold()
                pieces = set(normalized.replace("-", "_").split("_"))
                if pieces & _FORBIDDEN_CLASSIC_FIELDS or any(
                    marker in normalized
                    for marker in (
                        "oracle_path",
                        "reference_path",
                        "callable",
                        "script",
                        "python",
                        "template",
                    )
                ):
                    found.append(path)
                visit(child, path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{prefix}[{index}]")

    for field in fields:
        path = field.name
        normalized = field.name.casefold()
        pieces = set(normalized.replace("-", "_").split("_"))
        if pieces & _FORBIDDEN_CLASSIC_FIELDS or any(
            marker in normalized
            for marker in (
                "oracle_path",
                "reference_path",
                "callable",
                "script",
                "python",
                "template",
            )
        ):
            found.append(path)
        visit(field.value, path)
    return tuple(found)


class ClassicRecipeIntervention(InterventionBase):
    """A data-only invocation of one closed classic recipe family.

    Project data selects a family and role but never self-asserts a primary source
    origin.  The runtime assigns ``certified-project-overlay`` only after the closed
    ``source_overlay_graph`` validator proves typed source evidence plus any exact
    sparse declaration-counterfactual compiler audits and effective invocations;
    ``donor_source_overlay`` remains donor-private.
    """

    kind: Literal["classic_recipe"] = "classic_recipe"
    family: ClassicRecipeFamily
    role: ClassicRecipeRole
    build_target: BuildTarget
    symbol: Annotated[str, Field(min_length=1, max_length=2048)] | None = None
    parameters: tuple[ClassicField, ...] = ()

    @model_validator(mode="after")
    def validate_classic_recipe(self) -> ClassicRecipeIntervention:
        names = [field.name for field in self.parameters]
        if names != sorted(names) or len(names) != len(set(names)):
            raise ValueError("classic recipe parameters must be unique and canonically ordered")
        if self.role is ClassicRecipeRole.FUNCTION:
            if self.symbol is None:
                raise ValueError("classic function recipe requires symbol")
            if self.scope.function != self.symbol:
                raise ValueError("classic function recipe scope must name its exact symbol")
            if len(self.dependencies) != 1:
                raise ValueError("classic function recipe requires one primary donor")
        else:
            if self.symbol is not None:
                raise ValueError("only classic function recipes may name a symbol")
            if self.scope.function is not None:
                raise ValueError("classic donor/project recipe cannot have function scope")
        if self.role is ClassicRecipeRole.DONOR and self.scope.translation_unit is None:
            raise ValueError("classic donor recipe requires translation-unit scope")
        if self.role is ClassicRecipeRole.PROJECT and self.scope.translation_unit is not None:
            raise ValueError("classic project recipe requires target scope")
        if self.family is ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION:
            raise ValueError("simulated elision must use legacy.oracle_install quarantine")
        forbidden = _forbidden_classic_paths(self.parameters)
        if forbidden:
            raise ValueError(f"classic recipe contains forbidden payload fields: {forbidden}")
        return self


class OracleInstallRange(StrictModel):
    preimage_range: ByteRange
    output_range: ByteRange
    oracle_range: ByteRange

    @model_validator(mode="after")
    def copied_lengths_match(self) -> OracleInstallRange:
        if self.output_range.length != self.oracle_range.length:
            raise ValueError("oracle and output range lengths must match")
        return self


class LegacyOracleInstallIntervention(InterventionBase):
    kind: Literal["legacy.oracle_install"] = "legacy.oracle_install"
    allowlist_digest: Digest
    proof_receipt_digest: Digest
    preimage_digest: Digest
    oracle_body_digest: Digest
    oracle_target: Identifier
    oracle_address: Annotated[int, Field(ge=0)]
    ranges: Annotated[tuple[OracleInstallRange, ...], Field(min_length=1)]
    byte_count: Annotated[int, Field(gt=0)]
    maximum_oracle_payload_bytes: Annotated[int, Field(gt=0)]

    @classmethod
    def freeze(cls, **fields: Any) -> Self:
        """Create an intervention whose complete canonical shape is self-pinned."""

        if "allowlist_digest" in fields:
            raise ValueError("freeze computes the legacy allowlist digest")
        placeholder = cls.model_construct(
            allowlist_digest=Digest(value="0" * 64),
            **fields,
        )
        return cls.model_validate(
            {
                **fields,
                "allowlist_digest": legacy_allowlist_digest(placeholder),
            }
        )

    @model_validator(mode="after")
    def validate_ranges(self) -> LegacyOracleInstallIntervention:
        ordered = sorted((item.output_range for item in self.ranges), key=lambda item: item.offset)
        if tuple(ordered) != tuple(item.output_range for item in self.ranges):
            raise ValueError("oracle install ranges must be in canonical output order")
        if any(left.overlaps(right) for left, right in pairwise(ordered)):
            raise ValueError("oracle install ranges overlap")
        preimages = tuple(item.preimage_range for item in self.ranges)
        if any(left.overlaps(right) for left, right in pairwise(preimages)):
            raise ValueError("oracle install preimage ranges overlap")
        if any(item.oracle_range != item.output_range for item in self.ranges):
            raise ValueError("oracle install ranges must bind oracle and output offsets")
        if sum(item.length for item in ordered) != self.byte_count:
            raise ValueError("byte_count must equal the sum of range lengths")
        if self.maximum_oracle_payload_bytes < self.byte_count:
            raise ValueError("oracle payload ceiling cannot be smaller than installed bytes")
        if self.allowlist_digest != legacy_allowlist_digest(self):
            raise ValueError("legacy oracle install differs from its full-action allowlist")
        return self


def legacy_allowlist_digest(intervention: LegacyOracleInstallIntervention) -> Digest:
    """Bind every action field except the self-referential allowlist digest."""

    material = intervention.model_dump(mode="json", exclude={"allowlist_digest"})
    return Digest.from_bytes(canonical_json(material))


Intervention: TypeAlias = Annotated[
    StateCarrierIntervention
    | GeneratedSupplierIntervention
    | MetadataNormalizationIntervention
    | LinkOrderingIntervention
    | EqualBodyDonorIntervention
    | StructuralDonorIntervention
    | CrossTuDonorIntervention
    | SemanticRewriteIntervention
    | BinarySurgeryIntervention
    | ClassicRecipeIntervention
    | LegacyOracleInstallIntervention,
    Field(discriminator="kind"),
]


def intervention_authority_digest(intervention: Intervention) -> Digest:
    """Bind the complete canonical authority of one typed intervention."""

    return Digest.from_bytes(
        canonical_json(
            {
                "schema": "reprobit-intervention-authority-v1",
                "intervention": intervention.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                ),
            }
        )
    )


class InterventionDocument(StrictModel):
    schema_version: Literal[3]
    target_id: Identifier
    translation_unit_id: Identifier | None = None
    source: RelativePath | None = None
    source_digest: Digest | None = None
    build_target: BuildTarget | None = None
    interventions: tuple[Intervention, ...] = ()

    @field_validator("source")
    @classmethod
    def validate_source(cls, value: str | None) -> str | None:
        return _check_relative_path(value) if value is not None else None

    @model_validator(mode="after")
    def validate_contents(self) -> InterventionDocument:
        _require_unique((item.id for item in self.interventions), "intervention id")
        for item in self.interventions:
            if item.scope.target != self.target_id:
                raise ValueError(f"intervention {item.id!r} targets a different target")
            if self.translation_unit_id is None and item.scope.translation_unit is not None:
                raise ValueError(
                    f"translation-unit-scoped intervention {item.id!r} requires a "
                    "translation-unit shard"
                )
            if (
                self.translation_unit_id is not None
                and item.scope.translation_unit != self.translation_unit_id
            ):
                raise ValueError(f"intervention {item.id!r} has a different translation unit")
        return self


class ProofDocument(StrictModel):
    """Committed expected pins; never authoritative runtime proof results."""

    schema_version: Literal[3]
    target_id: Identifier
    translation_unit_id: Identifier | None = None
    expected_observations: tuple[ClassicProofReceipt, ...] = ()

    @model_validator(mode="after")
    def identifiers_are_unique(self) -> ProofDocument:
        _require_unique((item.id for item in self.expected_observations), "expected receipt id")
        return self


class ClassicProofRedaction(StrictModel):
    """Digest-only pin for one forbidden raw payload field."""

    source_path: Annotated[str, Field(min_length=1, max_length=4096)]
    evidence_digest: Digest


class ClassicProofReceipt(StrictModel):
    kind: Literal["expected_observations"] = "expected_observations"
    id: Identifier
    intervention_id: Identifier
    family: ClassicRecipeFamily
    expected_values: dict[str, NativeJsonValue] = Field(default_factory=dict)
    redactions: tuple[ClassicProofRedaction, ...] = ()
    status: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    authenticity: Annotated[str, Field(min_length=1, max_length=256)] | None = None

    @model_validator(mode="after")
    def redaction_paths_are_unique(self) -> ClassicProofReceipt:
        paths = [item.source_path for item in self.redactions]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("proof redactions must be unique and canonically ordered")
        return self


ClassicGroupOrderSymbol: TypeAlias = Annotated[
    str,
    Field(min_length=1, max_length=2048, pattern=r"^[^\x00]+$"),
]
ClassicGroupOrder: TypeAlias = Annotated[
    tuple[ClassicGroupOrderSymbol, ...],
    Field(min_length=2, max_length=512),
]


class ClassicGroupOrderPlan(StrictModel):
    """One explicit COMDAT group-order transform applied after composition."""

    operation: Literal["restore_comdat_group_order", "swap_comdat_group_order"]
    orders: Annotated[tuple[ClassicGroupOrder, ...], Field(min_length=1, max_length=512)]

    @field_validator("orders")
    @classmethod
    def validate_orders(cls, value: tuple[tuple[str, ...], ...]) -> tuple[tuple[str, ...], ...]:
        for order in value:
            if len(order) != len(set(order)):
                raise ValueError("COMDAT group-order symbols must be unique within each order")
        return value


class ClassicTranslationUnitPlan(StrictModel):
    """Reviewed translation-unit binding whose source digest pins effective bytes."""

    id: Identifier
    target_id: Identifier
    build_target: BuildTarget
    source: RelativePath
    source_digest: Digest
    group_order: ClassicGroupOrderPlan | None = None

    @field_validator("source")
    @classmethod
    def validate_source(cls, value: str) -> str:
        return _check_relative_path(value)


class ClassicTargetGate(StrictModel):
    target_id: Identifier
    build_target: BuildTarget


class ClassicArchiveCompletion(StrictModel):
    """Explicit authority to consume one otherwise forbidden archive payload."""

    state: Literal["authorized_exact_archive_materialization_enabled"]
    may_supply_linker_payload: Literal[True]
    reason: Annotated[str, Field(min_length=1, max_length=4096)]


class ClassicArchiveLinkContract(StrictModel):
    """Reviewed occurrences of one quarantined archive in a target link sequence."""

    target: Identifier
    direct_link_sequence: Annotated[tuple[str, ...], Field(min_length=1)]
    occurrences: Annotated[int, Field(ge=1)]

    @field_validator("direct_link_sequence")
    @classmethod
    def validate_sequence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item or "\x00" in item for item in value):
            raise ValueError("archive link sequence entries must be non-empty")
        if any(
            re.fullmatch(
                r"[A-Za-z][A-Za-z0-9._+-]{0,127}(?:::[A-Za-z][A-Za-z0-9._+-]{0,127})?",
                item,
            )
            is None
            for item in value
        ):
            raise ValueError("archive link sequence entries must be library identities")
        return value


class ClassicArchiveAuthority(StrictModel):
    """Finite, digest-pinned exception for one named third-party archive."""

    identity: Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9._+-]{0,127}$")]
    imported_target: Annotated[
        str,
        Field(pattern=r"^[A-Za-z][A-Za-z0-9._+-]{0,127}::[A-Za-z][A-Za-z0-9._+-]{0,127}$"),
    ]
    kind: Literal["third_party_reconstructed_archive"]
    source: RelativePath
    source_sha256: Sha256Hex
    payload_policy: Literal["retail_bytes_explicitly_allowed_for_named_third_party_archive_only"]
    completion: ClassicArchiveCompletion
    link_contract: Annotated[tuple[ClassicArchiveLinkContract, ...], Field(min_length=1)]

    @field_validator("source")
    @classmethod
    def validate_source(cls, value: str) -> str:
        checked = _check_relative_path(value)
        if PurePosixPath(checked).suffix.casefold() != ".lib":
            raise ValueError("quarantine archive authority must name one .lib file")
        return checked

    @model_validator(mode="after")
    def contracts_are_unique(self) -> ClassicArchiveAuthority:
        keys = [
            (item.target, tuple(value.casefold() for value in item.direct_link_sequence))
            for item in self.link_contract
        ]
        if len(keys) != len(set(keys)):
            raise ValueError("archive link contracts must be unique")
        for contract in self.link_contract:
            if (
                sum(
                    item.casefold() == self.imported_target.casefold()
                    for item in contract.direct_link_sequence
                )
                != 1
            ):
                raise ValueError(
                    "archive link sequence must contain its imported target exactly once"
                )
        return self


class ClassicSdkArchiveAuthority(StrictModel):
    """Digest-pinned external SDK library selected through a project LIBPATH."""

    path: RelativePath
    sha256: Sha256Hex

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        checked = _check_relative_path(value)
        if PurePosixPath(checked).suffix.casefold() != ".lib":
            raise ValueError("project SDK archive authority must name one .lib file")
        return checked


class BuildPlanDocument(StrictModel):
    """Declarative build authority not owned by intervention or proof shards.

    ``source_overlay_interventions`` names project-level ``source_overlay_graph``
    authority.  It does not admit donor-private ``donor_source_overlay`` recipes to
    a primary compiler seat.
    """

    schema_version: Literal[3]
    source_manifest_digest: Digest
    translation_units: tuple[ClassicTranslationUnitPlan, ...]
    source_overlay_digest: Digest
    source_overlay_interventions: tuple[Identifier, ...]
    archives: tuple[ClassicArchiveAuthority, ...]
    analysis_link_options: Annotated[tuple[Literal["/DEBUG"], ...], Field(max_length=1)] = ()
    project_sdk_libraries: tuple[ClassicSdkArchiveAuthority, ...] = ()
    target_gates: tuple[ClassicTargetGate, ...]

    @model_validator(mode="after")
    def identifiers_are_unique(self) -> BuildPlanDocument:
        _require_unique((item.id for item in self.translation_units), "build-plan TU id")
        _require_unique((item.target_id for item in self.target_gates), "target gate id")
        archive_identities = [item.identity.casefold() for item in self.archives]
        archive_targets = [item.imported_target.casefold() for item in self.archives]
        archive_sources = [item.source.casefold() for item in self.archives]
        _require_unique(archive_identities, "archive identity")
        _require_unique(archive_targets, "archive imported target")
        _require_unique(archive_sources, "archive source")
        sdk_source_list = [item.path.casefold() for item in self.project_sdk_libraries]
        _require_unique(sdk_source_list, "project SDK archive path")
        overlap = set(sdk_source_list) & set(archive_sources)
        if overlap:
            raise ValueError(f"archive paths cannot hold two authority classes: {sorted(overlap)}")
        return self


@dataclass(frozen=True, slots=True)
class ClassicDebugCompanionPaths:
    """Derived public seats for one noncertifying image/PDB analysis pair."""

    target_id: str
    image: str
    pdb: str


class _ProtectedPathClaims:
    """Project paths a debug-companion output may neither alias nor overlap.

    Each claim is keyed by its folded path and numbered by arrival. ``_beneath``
    maps every proper ancestor directory of a claimed path to the earliest
    claim below it, so testing one path costs a walk over its own ancestors
    instead of a scan of every earlier claim. When several earlier claims
    overlap, the earliest one is reported, exactly as a full scan in arrival
    order would report it.
    """

    __slots__ = ("_beneath", "_claims")

    def __init__(self) -> None:
        self._claims: dict[str, tuple[int, str]] = {}
        self._beneath: dict[str, tuple[int, str]] = {}

    def claim(self, relative: str, owner: str) -> None:
        folded = relative.replace("\\", "/").casefold()
        previous = self._claims.get(folded)
        if previous is not None:
            raise ValueError(f"debug-companion path {relative!r} aliases protected {previous[1]}")
        ancestors: list[str] = []
        separator = folded.find("/")
        while separator != -1:
            ancestors.append(folded[:separator])
            separator = folded.find("/", separator + 1)
        overlapping = [
            hit for ancestor in ancestors if (hit := self._claims.get(ancestor)) is not None
        ]
        below = self._beneath.get(folded)
        if below is not None:
            overlapping.append(below)
        if overlapping:
            _, overlap = min(overlapping)
            raise ValueError(f"debug-companion path {relative!r} overlaps protected {overlap}")
        entry = (len(self._claims), owner)
        self._claims[folded] = entry
        for ancestor in ancestors:
            self._beneath.setdefault(ancestor, entry)


def classic_debug_companion_paths(
    bundle: ProjectBundle,
) -> tuple[ClassicDebugCompanionPaths, ...]:
    """Derive isolated debug-companion pairs without new manifest authority."""

    if bundle.build_plan is None:
        return ()
    if not bundle.build_plan.analysis_link_options:
        return ()
    if bundle.source_manifest is None:
        raise ValueError("debug-companion outputs require a complete source manifest")

    claims = _ProtectedPathClaims()
    claim = claims.claim
    for target in bundle.spec.targets:
        claim(target.artifact, f"target artifact for {target.id!r}")
        claim(target.oracle, f"verification oracle for {target.id!r}")
    for entry in bundle.source_manifest.entries:
        claim(entry.path, f"source-manifest entry {entry.path!r}")
    for relative, owner in (
        (bundle.spec.toolchain.lock_file, "toolchain lock"),
        (bundle.spec.layout.source_manifest, "source manifest"),
        (bundle.spec.layout.build_plan, "build plan"),
        (bundle.spec.layout.producer_graph, "producer graph"),
    ):
        claim(relative, owner)

    protected_roots = tuple(
        value.replace("\\", "/").rstrip("/").casefold()
        for value in (
            bundle.spec.state_dir,
            bundle.spec.layout.interventions,
            bundle.spec.layout.proofs,
            bundle.spec.layout.oracles,
        )
    )
    derived: list[ClassicDebugCompanionPaths] = []
    for target in bundle.spec.targets:
        artifact = PurePosixPath(target.artifact)
        companion_root = artifact.parent / "reprobit-debug"
        image = (companion_root / artifact.name).as_posix()
        pdb = (companion_root / artifact.with_suffix(".PDB").name).as_posix()
        for relative, kind in ((image, "image"), (pdb, "PDB")):
            folded = relative.casefold()
            protected_root = next(
                (
                    root
                    for root in protected_roots
                    if folded == root or folded.startswith(root + "/")
                ),
                None,
            )
            if protected_root is not None:
                raise ValueError(
                    f"debug-companion {kind} path {relative!r} enters protected "
                    f"project root {protected_root!r}"
                )
            claim(relative, f"debug-companion {kind} for {target.id!r}")
        derived.append(ClassicDebugCompanionPaths(target.id, image, pdb))
    return tuple(derived)


def _validate_archive_link_contracts(
    plan: BuildPlanDocument,
    graph: ProducerGraphDocument,
    target_ids: set[str],
) -> None:
    """Bind every quarantined archive occurrence to its reviewed terminal site."""

    authorities = {item.source.casefold(): item for item in plan.archives}
    linker_nodes = {node.target_id: node for node in graph.nodes if node.target_id is not None}
    sequences: dict[str, tuple[str, ...]] = {}
    actual_sites: dict[str, set[tuple[str, int]]] = {source: set() for source in authorities}
    for target_id, node in linker_nodes.items():
        references = linker_library_sequence(node)
        identities: list[str] = []
        for ordinal, reference in enumerate(references):
            kind, relative = reference.split("/", 1)
            if kind == "quarantine-archive":
                authority = authorities.get(relative.casefold())
                if authority is None:
                    raise ValueError(f"linker {node.id!r} uses an unauthorized quarantine archive")
                identities.append(authority.imported_target)
                actual_sites[relative.casefold()].add((target_id, ordinal))
            else:
                identities.append(PurePosixPath(relative).stem)
        sequences[target_id] = tuple(identities)

    for authority in plan.archives:
        covered_sites: set[tuple[str, int]] = set()
        imported = authority.imported_target.casefold()
        for contract in authority.link_contract:
            if contract.target not in target_ids:
                raise ValueError(f"archive {authority.identity!r} contract names an unknown target")
            actual = tuple(item.casefold() for item in sequences[contract.target])
            expected = tuple(item.casefold() for item in contract.direct_link_sequence)
            starts = tuple(
                index
                for index in range(len(actual) - len(expected) + 1)
                if actual[index : index + len(expected)] == expected
            )
            if len(starts) != contract.occurrences:
                raise ValueError(
                    f"archive {authority.identity!r} link contract occurrence count "
                    f"differs for target {contract.target!r}"
                )
            imported_offset = expected.index(imported)
            for start in starts:
                site = (contract.target, start + imported_offset)
                if site in covered_sites:
                    raise ValueError(f"archive {authority.identity!r} link contracts overlap")
                covered_sites.add(site)
        expected_sites = actual_sites[authority.source.casefold()]
        if covered_sites != expected_sites:
            missing = sorted(expected_sites - covered_sites)
            extra = sorted(covered_sites - expected_sites)
            raise ValueError(
                f"archive {authority.identity!r} link sites differ from its finite "
                f"authority; missing={missing}, extra={extra}"
            )


ProofDocument.model_rebuild()


class OracleFunction(StrictModel):
    translation_unit: Identifier
    symbol: Annotated[str, Field(min_length=1, max_length=2048)]
    address: Annotated[int, Field(ge=0)]
    size: Annotated[int, Field(gt=0)]
    digest: Digest


class OracleDocument(StrictModel):
    schema_version: Literal[3]
    target_id: Identifier
    image_size: Annotated[int, Field(gt=0)]
    image_digest: Digest
    required_row_count: Annotated[int, Field(ge=0)] | None = None
    row_identity_digest: Digest | None = None
    functions: tuple[OracleFunction, ...] = ()


class ProjectBundle(StrictModel):
    """A fully loaded, cross-validated project tree."""

    root: str = Field(exclude=True)
    spec: ProjectSpec
    toolchain_lock: ToolchainLock
    source_manifest: SourceManifestDocument | None = None
    build_plan: BuildPlanDocument | None = None
    producer_graph: ProducerGraphDocument | None = None
    intervention_documents: tuple[InterventionDocument, ...]
    proof_documents: tuple[ProofDocument, ...]
    oracle_documents: tuple[OracleDocument, ...]

    @property
    def interventions(self) -> tuple[Intervention, ...]:
        return tuple(
            intervention
            for document in self.intervention_documents
            for intervention in document.interventions
        )

    @model_validator(mode="after")
    def validate_tree(self) -> ProjectBundle:
        if self.toolchain_lock.profile != self.spec.toolchain.profile:
            raise ValueError("toolchain lock profile does not match project profile")
        project_root = Path(self.root).resolve(strict=False)
        resolved_target_paths: dict[Path, tuple[str, str]] = {}
        for target in self.spec.targets:
            for kind, relative in (("artifact", target.artifact), ("oracle", target.oracle)):
                resolved = project_root.joinpath(*relative.replace("\\", "/").split("/")).resolve(
                    strict=False
                )
                try:
                    resolved.relative_to(project_root)
                except ValueError as exc:
                    raise ValueError(
                        f"target {kind} path escapes project root: {relative!r}"
                    ) from exc
                if previous := resolved_target_paths.get(resolved):
                    raise ValueError(
                        "target artifact/oracle paths must resolve uniquely; "
                        f"{previous[0]} for {previous[1]!r} and {kind} for "
                        f"{target.id!r} resolve to {resolved}"
                    )
                resolved_target_paths[resolved] = (kind, target.id)
        target_ids = {target.id for target in self.spec.targets}
        oracle_ids = {document.target_id for document in self.oracle_documents}
        if oracle_ids != target_ids:
            missing = sorted(target_ids - oracle_ids)
            extra = sorted(oracle_ids - target_ids)
            raise ValueError(f"oracle target mismatch; missing={missing}, extra={extra}")
        all_documents: tuple[InterventionDocument | ProofDocument, ...] = (
            *self.intervention_documents,
            *self.proof_documents,
        )
        if any(document.target_id not in target_ids for document in all_documents):
            raise ValueError("manifest document names an unknown target")
        if self.source_manifest is not None and not self.source_manifest.complete:
            raise ValueError("certifiable bundles require a complete portable source manifest")
        if self.source_manifest is not None:
            forbidden_source_paths = {
                "reprobit.toml",
                self.spec.toolchain.lock_file.replace("\\", "/").casefold(),
                self.spec.layout.source_manifest.replace("\\", "/").casefold(),
                self.spec.layout.build_plan.replace("\\", "/").casefold(),
                self.spec.layout.producer_graph.replace("\\", "/").casefold(),
                *(target.artifact.replace("\\", "/").casefold() for target in self.spec.targets),
                *(target.oracle.replace("\\", "/").casefold() for target in self.spec.targets),
            }
            forbidden_roots = tuple(
                value.replace("\\", "/").rstrip("/").casefold() + "/"
                for value in (
                    self.spec.state_dir,
                    self.spec.layout.interventions,
                    self.spec.layout.proofs,
                    self.spec.layout.oracles,
                )
            )
            for entry in self.source_manifest.entries:
                folded = entry.path.casefold()
                if folded in forbidden_source_paths or folded.startswith(forbidden_roots):
                    raise ValueError(
                        f"source manifest admits control, output, or oracle path {entry.path!r}"
                    )
        if self.build_plan is not None:
            if self.source_manifest is None:
                raise ValueError("build plan requires a portable source manifest")
            classic_debug_companion_paths(self)
            actual_source_manifest_digest = source_manifest_digest(self.source_manifest)
            if self.build_plan.source_manifest_digest != actual_source_manifest_digest:
                raise ValueError("build-plan source manifest digest does not match its document")
            planned_targets = {item.target_id for item in self.build_plan.target_gates}
            if planned_targets != target_ids:
                raise ValueError("build-plan target gates do not match project targets")
            if any(item.target_id not in target_ids for item in self.build_plan.translation_units):
                raise ValueError("build plan names an unknown target")
            manifest_entries = {item.path.casefold(): item for item in self.source_manifest.entries}
            for archive in self.build_plan.archives:
                source_entry = manifest_entries.get(archive.source.casefold())
                if source_entry is None:
                    raise ValueError(
                        f"quarantine archive is absent from source authority: {archive.source!r}"
                    )
                if source_entry.digest.value != archive.source_sha256:
                    raise ValueError(
                        f"quarantine archive digest differs from source authority: "
                        f"{archive.source!r}"
                    )
            for sdk_archive in self.build_plan.project_sdk_libraries:
                source_entry = manifest_entries.get(sdk_archive.path.casefold())
                if source_entry is None:
                    raise ValueError(
                        f"project SDK archive is absent from source authority: {sdk_archive.path!r}"
                    )
                if source_entry.digest.value != sdk_archive.sha256:
                    raise ValueError(
                        f"project SDK archive digest differs from source authority: "
                        f"{sdk_archive.path!r}"
                    )
        interventions = self.interventions
        overlay_outputs: dict[str, str] = {}
        if self.source_manifest is not None:
            manifest_source_paths = {
                item.path.casefold(): item.path for item in self.source_manifest.entries
            }
            for intervention in interventions:
                if not (
                    isinstance(intervention, ClassicRecipeIntervention)
                    and intervention.family is ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
                ):
                    continue
                values = {item.name: item.value for item in intervention.parameters}
                outputs = values.get("outputs")
                if not isinstance(outputs, list):
                    raise ValueError("source-overlay outputs are malformed")
                for output in outputs:
                    if not isinstance(output, dict) or not isinstance(output.get("path"), str):
                        raise ValueError("source-overlay output is malformed")
                    output_path = output["path"]
                    assert isinstance(output_path, str)
                    canonical = _check_relative_path(output_path)
                    folded = canonical.casefold()
                    if folded in overlay_outputs:
                        raise ValueError(f"source-overlay output repeats {canonical!r}")
                    manifest_path = manifest_source_paths.get(folded)
                    if "clean" in output:
                        if manifest_path is None:
                            raise ValueError(
                                "clean source-overlay output is absent from the source "
                                f"manifest: {canonical!r}"
                            )
                        if manifest_path != canonical:
                            raise ValueError(
                                "clean source-overlay output spelling differs from the "
                                f"source manifest: {canonical!r}, {manifest_path!r}"
                            )
                    elif manifest_path is not None:
                        raise ValueError(
                            "generated source-overlay output collides with source manifest: "
                            f"{canonical!r}, {manifest_path!r}"
                        )
                    overlay_outputs[folded] = canonical
        if self.producer_graph is not None:
            if self.source_manifest is None:
                raise ValueError("producer graph requires a portable source manifest")
            if self.producer_graph.toolchain_lock_digest != toolchain_document_digest(
                self.toolchain_lock
            ):
                raise ValueError("producer graph toolchain-lock binding differs")
            if self.producer_graph.path_profile_id != self.spec.paths.id:
                raise ValueError("producer graph logical-path profile differs")
            graph_targets = {
                node.target_id for node in self.producer_graph.nodes if node.target_id is not None
            }
            if graph_targets != target_ids:
                missing = sorted(target_ids - graph_targets)
                extra = sorted(graph_targets - target_ids)
                raise ValueError(
                    f"producer graph target mismatch; missing={missing}, extra={extra}"
                )
            target_artifacts = {
                target.id: target.artifact.replace("\\", "/") for target in self.spec.targets
            }
            for node in self.producer_graph.nodes:
                if node.target_id is None:
                    continue
                expected = target_artifacts[node.target_id]
                if expected not in node.outputs:
                    raise ValueError(
                        f"terminal producer {node.id!r} does not publish the exact "
                        f"project artifact {expected!r}"
                    )
            if not producer_graph_accepts_source(
                self.producer_graph,
                paths=(item.path for item in self.source_manifest.entries),
                overlay_outputs=overlay_outputs.values(),
            ):
                raise ValueError("producer graph reads source outside reviewed authority")
            quarantine_references = {
                input_ref.removeprefix("quarantine-archive/").casefold()
                for node in self.producer_graph.nodes
                for input_ref in node.inputs
                if input_ref.startswith("quarantine-archive/")
            }
            authorized_archives = (
                {archive.source.casefold() for archive in self.build_plan.archives}
                if self.build_plan is not None
                else set()
            )
            if quarantine_references != authorized_archives:
                missing = sorted(authorized_archives - quarantine_references)
                extra = sorted(quarantine_references - authorized_archives)
                raise ValueError(
                    "producer quarantine archives do not match build-plan authority; "
                    f"missing={missing}, extra={extra}"
                )
            if self.build_plan is not None:
                _validate_archive_link_contracts(self.build_plan, self.producer_graph, target_ids)
        _require_unique((item.id for item in interventions), "intervention id")
        direct_function_scopes = {
            (
                item.scope.target,
                item.scope.translation_unit,
                item.scope.function,
            )
            for item in interventions
            if item.scope.function is not None
        }
        oracle_function_scopes = {
            (document.target_id, item.translation_unit, item.symbol)
            for document in self.oracle_documents
            for item in document.functions
        }
        authoritative_function_scopes = direct_function_scopes | oracle_function_scopes
        for item in interventions:
            for beneficiary in item.beneficiaries:
                key = (
                    beneficiary.target,
                    beneficiary.translation_unit,
                    beneficiary.function,
                )
                if key not in authoritative_function_scopes:
                    raise ValueError(
                        f"intervention {item.id!r} allocates cost to an unknown "
                        f"function scope: {key!r}"
                    )
        legacy_interventions = {
            item.id: item
            for item in interventions
            if isinstance(item, LegacyOracleInstallIntervention)
        }
        declared_allowlist = {
            item.intervention_id: item for item in self.spec.authenticity.legacy_allowlist
        }
        if set(legacy_interventions) != set(declared_allowlist):
            missing = sorted(set(legacy_interventions) - set(declared_allowlist))
            extra = sorted(set(declared_allowlist) - set(legacy_interventions))
            raise ValueError(f"legacy allowlist mismatch; missing={missing}, extra={extra}")
        for intervention_id, legacy_action in legacy_interventions.items():
            pin = declared_allowlist[intervention_id]
            if (
                pin.allowlist_digest != legacy_action.allowlist_digest
                or pin.proof_receipt_digest != legacy_action.proof_receipt_digest
                or pin.range_count != len(legacy_action.ranges)
                or pin.byte_count != legacy_action.byte_count
                or pin.maximum_oracle_payload_bytes != legacy_action.maximum_oracle_payload_bytes
            ):
                raise ValueError(f"legacy allowlist pin mismatch for {intervention_id!r}")
        intervention_ids = {item.id for item in interventions}
        for item in interventions:
            unknown = set(item.dependencies) - intervention_ids
            if unknown:
                raise ValueError(
                    f"intervention {item.id!r} has dangling dependencies: {sorted(unknown)}"
                )
        receipts = tuple(
            receipt
            for document in self.proof_documents
            for receipt in document.expected_observations
        )
        _validate_classic_donor_beneficiaries(interventions, receipts)
        _reject_dependency_cycles(interventions)
        if self.build_plan is not None:
            overlay_ids = {
                item.id
                for item in interventions
                if isinstance(item, ClassicRecipeIntervention)
                and item.family is ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
            }
            planned_overlay_ids = set(self.build_plan.source_overlay_interventions)
            if len(planned_overlay_ids) != len(self.build_plan.source_overlay_interventions):
                raise ValueError("build-plan source overlay intervention ids repeat")
            if planned_overlay_ids != overlay_ids:
                missing = sorted(overlay_ids - planned_overlay_ids)
                extra = sorted(planned_overlay_ids - overlay_ids)
                raise ValueError(
                    "build-plan source overlay interventions do not match authority; "
                    f"missing={missing}, extra={extra}"
                )

            translation_unit_documents = {
                document.translation_unit_id: document
                for document in self.intervention_documents
                if document.translation_unit_id is not None
            }
            translation_unit_ids = [
                document.translation_unit_id
                for document in self.intervention_documents
                if document.translation_unit_id is not None
            ]
            _require_unique(translation_unit_ids, "intervention translation-unit id")
            planned_units = {item.id: item for item in self.build_plan.translation_units}
            if set(planned_units) != set(translation_unit_documents):
                missing = sorted(set(translation_unit_documents) - set(planned_units))
                extra = sorted(set(planned_units) - set(translation_unit_documents))
                raise ValueError(
                    "build-plan translation units do not match intervention shards; "
                    f"missing={missing}, extra={extra}"
                )
            for unit_id, plan in planned_units.items():
                document = translation_unit_documents[unit_id]
                if (
                    document.target_id != plan.target_id
                    or document.source != plan.source
                    or document.source_digest != plan.source_digest
                    or document.build_target != plan.build_target
                ):
                    raise ValueError(
                        f"build-plan translation unit {unit_id!r} does not match its shard"
                    )
        _require_unique((item.id for item in receipts), "classic receipt id")
        _require_unique(
            (item.intervention_id for item in receipts),
            "classic receipt intervention id",
        )
        dangling_receipts = {
            item.intervention_id
            for item in receipts
            if item.intervention_id not in intervention_ids
        }
        if dangling_receipts:
            raise ValueError(
                f"classic receipts name unknown interventions: {sorted(dangling_receipts)}"
            )
        expected_receipts = {
            item.id: item
            for item in interventions
            if isinstance(
                item,
                (ClassicRecipeIntervention, LegacyOracleInstallIntervention),
            )
        }
        received_receipts = {item.intervention_id: item for item in receipts}
        if set(received_receipts) != set(expected_receipts):
            missing = sorted(set(expected_receipts) - set(received_receipts))
            extra = sorted(set(received_receipts) - set(expected_receipts))
            raise ValueError(
                "classic expected receipts do not match interventions; "
                f"missing={missing}, extra={extra}"
            )
        receipt_documents = {
            receipt.intervention_id: document
            for document in self.proof_documents
            for receipt in document.expected_observations
        }
        intervention_documents = {
            intervention.id: document
            for document in self.intervention_documents
            for intervention in document.interventions
        }
        for intervention_id, receipt in received_receipts.items():
            intervention = expected_receipts[intervention_id]
            expected_family = (
                intervention.family
                if isinstance(intervention, ClassicRecipeIntervention)
                else ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION
            )
            if receipt.family is not expected_family:
                raise ValueError(f"classic receipt family does not match {intervention_id!r}")
            if (
                isinstance(intervention, LegacyOracleInstallIntervention)
                and Digest.from_bytes(canonical_json(receipt)) != intervention.proof_receipt_digest
            ):
                raise ValueError(f"legacy proof receipt digest does not match {intervention_id!r}")
            intervention_document = intervention_documents[intervention_id]
            receipt_document = receipt_documents[intervention_id]
            if (
                receipt_document.target_id != intervention_document.target_id
                or receipt_document.translation_unit_id != intervention_document.translation_unit_id
            ):
                raise ValueError(f"classic receipt target/TU does not match {intervention_id!r}")
        return self


class SchemaCatalog(StrictModel):
    """Synthetic aggregate used to emit a complete schema catalog."""

    project: ProjectSpec
    toolchain_lock: ToolchainLock
    source_manifest: SourceManifestDocument
    build_plan: BuildPlanDocument
    producer_graph: ProducerGraphDocument
    intervention_document: InterventionDocument
    proof_document: ProofDocument
    oracle_document: OracleDocument


def _require_unique(values: Iterable[str], label: str) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    if duplicates:
        raise ValueError(f"duplicate {label}: {', '.join(sorted(duplicates))}")


def candidate_auxiliary_donor_ids(
    values: Mapping[str, object],
    expected_values: Mapping[str, object] | None = None,
) -> tuple[str, ...]:
    """Return every non-primary donor selected by runtime candidate constraints."""

    merged = deepcopy(dict(values))
    expected = expected_values or {}
    for name in ("target_donor", "complete_donor", "instruction_donor", "donor_variants"):
        if name not in expected:
            continue
        if name in merged and merged[name] != expected[name]:
            raise ValueError(f"candidate constraint {name!r} conflicts with recipe intent")
        merged[name] = deepcopy(expected[name])
    for path in sorted(expected):
        value = expected[path]
        match = re.fullmatch(r"donor_variants\[([0-9]+)\]\.donor", path)
        if match is None:
            continue
        variants = merged.get("donor_variants")
        index = int(match.group(1))
        if not isinstance(variants, list) or index >= len(variants):
            raise ValueError(f"candidate constraint {path!r} leaves its array")
        variant = variants[index]
        if not isinstance(variant, dict):
            raise ValueError(f"candidate constraint {path!r} crosses a scalar")
        if "donor" in variant and variant["donor"] != value:
            raise ValueError(f"candidate constraint {path!r} conflicts with recipe intent")
        variant["donor"] = deepcopy(value)

    donor_ids: set[str] = set()
    for name in ("target_donor", "complete_donor", "instruction_donor"):
        value = merged.get(name)
        if value is None:
            continue
        if not isinstance(value, str):
            raise ValueError(f"candidate {name} is malformed")
        donor_ids.add(value)

    raw_variants = merged.get("donor_variants", [])
    if not isinstance(raw_variants, list):
        raise ValueError("candidate donor variants are malformed")
    for item in raw_variants:
        donor = item.get("donor") if isinstance(item, dict) else None
        if not isinstance(donor, str):
            raise ValueError("candidate donor variant is malformed")
        donor_ids.add(donor)
    return tuple(sorted(donor_ids))


def classic_function_donor_ids(
    intervention: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
) -> frozenset[str]:
    """Return every primary and candidate-selected donor used by a function record."""

    if intervention.role is not ClassicRecipeRole.FUNCTION:
        raise ValueError(f"intervention {intervention.id!r} is not a classic function")
    if receipt.intervention_id != intervention.id or receipt.family is not intervention.family:
        raise ValueError(f"proof receipt does not match classic function {intervention.id!r}")
    parameters = {field.name: field.value for field in intervention.parameters}
    return frozenset(
        (
            *intervention.dependencies,
            *candidate_auxiliary_donor_ids(parameters, receipt.expected_values),
        )
    )


def _validate_classic_donor_beneficiaries(
    interventions: tuple[Intervention, ...],
    receipts: tuple[ClassicProofReceipt, ...],
) -> None:
    """Keep donor cost allocation identical to every runtime consumer."""

    consumers: dict[str, dict[tuple[str, str, str], Scope]] = {}
    donors = {
        intervention.id: intervention
        for intervention in interventions
        if isinstance(intervention, ClassicRecipeIntervention)
        and intervention.role is ClassicRecipeRole.DONOR
    }
    receipts_by_intervention: dict[str, list[ClassicProofReceipt]] = {}
    for receipt in receipts:
        receipts_by_intervention.setdefault(receipt.intervention_id, []).append(receipt)
    for intervention in interventions:
        scope = intervention.scope
        if scope.function is None or scope.translation_unit is None:
            continue
        key = (scope.target, scope.translation_unit, scope.function)
        donor_ids = set(intervention.dependencies)
        if (
            isinstance(intervention, ClassicRecipeIntervention)
            and intervention.role is ClassicRecipeRole.FUNCTION
        ):
            matches = receipts_by_intervention.get(intervention.id, ())
            if len(matches) != 1:
                raise ValueError(f"intervention {intervention.id!r} requires one proof receipt")
            values = {field.name: field.value for field in intervention.parameters}
            auxiliary_ids = set(candidate_auxiliary_donor_ids(values, matches[0].expected_values))
            for donor_id in auxiliary_ids:
                donor = donors.get(donor_id)
                if donor is None:
                    raise ValueError(
                        f"classic function {intervention.id!r} names an unknown "
                        f"auxiliary donor: {donor_id!r}"
                    )
                if donor.scope.target != scope.target or (
                    donor.scope.translation_unit != scope.translation_unit
                ):
                    raise ValueError(
                        f"classic function {intervention.id!r} auxiliary donor "
                        f"{donor_id!r} is outside its target/TU"
                    )
            donor_ids.update(auxiliary_ids)
        for dependency in donor_ids:
            consumers.setdefault(dependency, {})[key] = scope

    for intervention in interventions:
        if not (
            isinstance(intervention, ClassicRecipeIntervention)
            and intervention.role is ClassicRecipeRole.DONOR
        ):
            continue
        expected = tuple(
            consumers.get(intervention.id, {})[key]
            for key in sorted(consumers.get(intervention.id, {}))
        )
        if intervention.beneficiaries != expected:
            raise ValueError(
                f"classic donor {intervention.id!r} beneficiaries differ from its runtime consumers"
            )


def _reject_dependency_cycles(interventions: tuple[Intervention, ...]) -> None:
    graph = {item.id: item.dependencies for item in interventions}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visited:
            return
        if node in visiting:
            raise ValueError(f"intervention dependency cycle includes {node!r}")
        visiting.add(node)
        for parent in graph[node]:
            visit(parent)
        visiting.remove(node)
        visited.add(node)

    for node in graph:
        visit(node)


def schema_catalog() -> JsonValue:
    """Return JSON Schema for all committed document kinds."""

    return _identified_schema(
        TypeAdapter(SchemaCatalog).json_schema(
            mode="validation",
            ref_template="#/$defs/{model}",
        ),
        "urn:reprobit:schema:catalog:3",
    )


def _identified_schema(schema: dict[str, Any], schema_id: str) -> JsonValue:
    """Attach a stable dialect and identity to one self-contained root schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": schema_id,
        **schema,
    }


def project_document_schemas() -> dict[str, JsonValue]:
    """Return usable root schemas for every committed project document."""

    roots: tuple[tuple[str, type[Any], str], ...] = (
        ("project-v3.schema.json", ProjectSpec, "urn:reprobit:schema:project:3"),
        (
            "toolchain-lock-v3.schema.json",
            ToolchainLock,
            "urn:reprobit:schema:toolchain-lock:3",
        ),
        (
            "source-manifest-v3.schema.json",
            SourceManifestDocument,
            "urn:reprobit:schema:source-manifest:3",
        ),
        (
            "build-plan-v3.schema.json",
            BuildPlanDocument,
            "urn:reprobit:schema:build-plan:3",
        ),
        (
            "producer-graph-v3.schema.json",
            ProducerGraphDocument,
            "urn:reprobit:schema:producer-graph:3",
        ),
        (
            "intervention-document-v3.schema.json",
            InterventionDocument,
            "urn:reprobit:schema:intervention-document:3",
        ),
        (
            "proof-document-v3.schema.json",
            ProofDocument,
            "urn:reprobit:schema:proof-document:3",
        ),
        (
            "oracle-document-v3.schema.json",
            OracleDocument,
            "urn:reprobit:schema:oracle-document:3",
        ),
    )
    schemas = {
        filename: _identified_schema(
            TypeAdapter(model).json_schema(
                mode="validation",
                ref_template="#/$defs/{model}",
            ),
            schema_id,
        )
        for filename, model, schema_id in roots
    }
    schemas["catalog-v3.schema.json"] = schema_catalog()
    return schemas


def write_json_schema(path: str | Path) -> None:
    """Write the canonical generated schema catalog."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    try:
        temporary.write_bytes(canonical_json(schema_catalog()))
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def write_project_document_schemas(directory: str | Path) -> None:
    """Atomically write every generated project-document schema asset."""

    destination = Path(directory)
    destination.mkdir(parents=True, exist_ok=True)
    for filename, schema in project_document_schemas().items():
        output = destination / filename
        temporary = output.with_name(f".{output.name}.tmp-{os.getpid()}")
        try:
            temporary.write_bytes(canonical_json(schema))
            os.replace(temporary, output)
        finally:
            temporary.unlink(missing_ok=True)


__all__ = [
    "AuthenticitySettings",
    "BinarySurgeryIntervention",
    "BinarySurgeryMethod",
    "BuildPlanDocument",
    "ClassicDebugCompanionPaths",
    "ClassicField",
    "ClassicGroupOrderPlan",
    "ClassicProofReceipt",
    "ClassicProofRedaction",
    "ClassicRecipeFamily",
    "ClassicRecipeIntervention",
    "ClassicRecipeRole",
    "ClassicSdkArchiveAuthority",
    "ClassicTargetGate",
    "ClassicTranslationUnitPlan",
    "CommandBuildAdapter",
    "CommandSpec",
    "CrossTuDonorIntervention",
    "EqualBodyDonorIntervention",
    "GeneratedSupplierIntervention",
    "InputTreeReceipt",
    "Intervention",
    "InterventionDocument",
    "LegacyAllowlistEntry",
    "LegacyOracleInstallIntervention",
    "LinkOrderingIntervention",
    "LiteralVerifier",
    "LockedTool",
    "LogicalPathProfile",
    "ManifestLayout",
    "MetadataNormalizationIntervention",
    "MsvcRelease",
    "OracleDocument",
    "OracleFunction",
    "OracleInstallRange",
    "ProducerGraphBuildAdapter",
    "ProjectBundle",
    "ProjectSpec",
    "ProofDocument",
    "SchemaError",
    "SchemaVersionError",
    "SemanticRewriteIntervention",
    "SemanticRewriteMethod",
    "SourceManifestDocument",
    "SourceManifestEntry",
    "StateCarrierIntervention",
    "StructuralDonorIntervention",
    "StructuralMode",
    "TargetSpec",
    "ToolchainLock",
    "ToolchainProfileSource",
    "ToolchainRef",
    "VerifierSpec",
    "candidate_auxiliary_donor_ids",
    "classic_debug_companion_paths",
    "classic_function_donor_ids",
    "intervention_authority_digest",
    "legacy_allowlist_digest",
    "project_document_schemas",
    "schema_catalog",
    "source_manifest_digest",
    "write_json_schema",
    "write_project_document_schemas",
]
