"""Durable contracts and pure state enumeration for intervention discovery."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Annotated, Literal, Protocol

from pydantic import Field, field_validator, model_validator

from reprobit.model import Digest, Identifier, Scope, StrictModel
from reprobit.process import CancellationToken
from reprobit.schema import Intervention
from reprobit.strict_json import JsonValue, canonical_json


class DiscoveryError(RuntimeError):
    """A discovery campaign is invalid, incomplete, or changed underneath us."""


class DeclarationFamily(StrEnum):
    """The small default set of declaration-only compiler-state families."""

    DECLARATION_SHAPE = "declaration_shape"
    PAD_SHAPE = "pad_shape"
    FORWARD_DECLARATION_RUN = "forward_declaration_run"
    EXTERN_RUN_PAIR = "extern_run_pair"


class DeclarationPlacement(StrEnum):
    PREFIX = "prefix"
    AFTER_INCLUDES = "after_includes"
    FORCE_INCLUDE = "force_include"
    SUFFIX = "suffix"


class DiscoveryFindingKind(StrEnum):
    WHOLE_BODY = "whole_body"
    PRIVATE_DONOR = "private_donor"
    INSTRUCTION_MOSAIC = "instruction_mosaic"


class InclusiveRange(StrictModel):
    """One finite, inclusive integer range used by a campaign plan."""

    start: Annotated[int, Field(ge=0)]
    stop: Annotated[int, Field(ge=0)]
    step: Annotated[int, Field(gt=0)] = 1

    @model_validator(mode="after")
    def ordered(self) -> InclusiveRange:
        if self.stop < self.start:
            raise ValueError("range stop must not precede its start")
        return self

    def values(self) -> range:
        return range(self.start, self.stop + 1, self.step)


class DeclarationShapeSearch(StrictModel):
    family: Literal[DeclarationFamily.DECLARATION_SHAPE]
    classes: InclusiveRange
    functions: InclusiveRange

    @model_validator(mode="after")
    def generator_domain(self) -> DeclarationShapeSearch:
        if not 1 <= self.classes.start <= self.classes.stop <= 10:
            raise ValueError("declaration-shape classes must stay in [1, 10]")
        if not 1 <= self.functions.start <= self.functions.stop <= 100:
            raise ValueError("declaration-shape functions must stay in [1, 100]")
        return self


class PadShapeSearch(StrictModel):
    family: Literal[DeclarationFamily.PAD_SHAPE]
    classes: InclusiveRange
    functions_per_class: InclusiveRange

    @model_validator(mode="after")
    def generator_domain(self) -> PadShapeSearch:
        if not 1 <= self.classes.start <= self.classes.stop <= 99:
            raise ValueError("pad-shape classes must stay in [1, 99]")
        if not (
            1
            <= self.functions_per_class.start
            <= self.functions_per_class.stop
            <= 99
        ):
            raise ValueError("pad-shape functions-per-class must stay in [1, 99]")
        return self


class ForwardDeclarationSearch(StrictModel):
    family: Literal[DeclarationFamily.FORWARD_DECLARATION_RUN]
    prefix: Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9]*$")]
    counts: InclusiveRange
    width: Annotated[int, Field(ge=1, le=3)]
    placements: Annotated[tuple[DeclarationPlacement, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def canonical_placements(self) -> ForwardDeclarationSearch:
        values = tuple(item.value for item in self.placements)
        if values != tuple(sorted(set(values))):
            raise ValueError("forward declaration placements must be unique and canonical")
        if self.counts.stop > 999 or self.counts.stop > 10**self.width:
            raise ValueError("forward declaration count is outside its fixed width")
        if self.counts.start < 1:
            raise ValueError("forward declaration count must be positive")
        return self


class ExternRunPairSearch(StrictModel):
    family: Literal[DeclarationFamily.EXTERN_RUN_PAIR]
    header_prefix: Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9_]*$")]
    seat_prefix: Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9_]*$")]
    header_counts: InclusiveRange
    seat_counts: InclusiveRange
    width: Annotated[int, Field(ge=1, le=3)]

    @model_validator(mode="after")
    def valid_counts(self) -> ExternRunPairSearch:
        if self.header_prefix == self.seat_prefix:
            raise ValueError("extern pair prefixes must be distinct")
        ceiling = 10**self.width
        if max(self.header_counts.stop, self.seat_counts.stop) > min(999, ceiling):
            raise ValueError("extern pair count is outside its fixed width")
        if self.header_counts.stop == 0 and self.seat_counts.stop == 0:
            raise ValueError("extern pair search cannot contain only the empty state")
        return self


DeclarationSearch = Annotated[
    DeclarationShapeSearch
    | PadShapeSearch
    | ForwardDeclarationSearch
    | ExternRunPairSearch,
    Field(discriminator="family"),
]

class MosaicLimits(StrictModel):
    enabled: bool = True
    max_donors: Annotated[int, Field(ge=1, le=2)] = 2
    max_ranges: Annotated[int, Field(ge=1, le=8)] = 8
    max_candidates_per_symbol: Annotated[int, Field(ge=1, le=256)] = 64
    max_search_steps: Annotated[int, Field(ge=1, le=100_000)] = 10_000


class DiscoveryPlan(StrictModel):
    """A completely finite declaration campaign."""

    schema_version: Literal[1] = 1
    target: Identifier
    translation_unit: Identifier
    symbols: tuple[Annotated[str, Field(min_length=1, max_length=2048)], ...] = ()
    searches: Annotated[tuple[DeclarationSearch, ...], Field(min_length=1)]
    max_cells: Annotated[int, Field(ge=1, le=10_000)]
    max_observed_functions: Annotated[int, Field(ge=1, le=100_000)] = 100_000
    mosaic: MosaicLimits = MosaicLimits()

    @model_validator(mode="after")
    def canonical_targets(self) -> DiscoveryPlan:
        if self.symbols != tuple(sorted(set(self.symbols), key=str.casefold)):
            raise ValueError("discovery symbols must be unique and canonical")
        return self


class DeclarationParameter(StrictModel):
    name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    value: int | str


class DeclarationState(StrictModel):
    """One closed declaration state with canonical scalar parameters."""

    family: DeclarationFamily
    parameters: Annotated[tuple[DeclarationParameter, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def canonical_parameters(self) -> DeclarationState:
        names = tuple(item.name for item in self.parameters)
        if names != tuple(sorted(set(names))):
            raise ValueError("declaration-state parameters must be unique and canonical")
        return self

    def parameter(self, name: str) -> int | str:
        for item in self.parameters:
            if item.name == name:
                return item.value
        raise DiscoveryError(f"declaration state lacks parameter {name!r}")


def _state(
    family: DeclarationFamily,
    **parameters: int | str,
) -> DeclarationState:
    return DeclarationState(
        family=family,
        parameters=tuple(
            DeclarationParameter(name=name, value=value)
            for name, value in sorted(parameters.items())
        ),
    )


def declaration_state_id(state: DeclarationState) -> str:
    digest = hashlib.sha256(canonical_json(state)).hexdigest()
    return f"state.{digest[:24]}"


def enumerate_declaration_states(plan: DiscoveryPlan) -> tuple[DeclarationState, ...]:
    """Expand and validate a campaign before any compiler process starts."""

    states: list[DeclarationState] = []
    identities: set[str] = set()

    def add(state: DeclarationState) -> None:
        identity = declaration_state_id(state)
        if identity in identities:
            raise DiscoveryError("declaration searches enumerate a duplicate state")
        if len(states) >= plan.max_cells:
            raise DiscoveryError(
                f"declaration campaign expands above max_cells {plan.max_cells}"
            )
        identities.add(identity)
        states.append(state)

    for search in plan.searches:
        if isinstance(search, DeclarationShapeSearch):
            for classes in search.classes.values():
                for functions in search.functions.values():
                    if classes <= functions <= 10 * classes:
                        add(
                            _state(
                                DeclarationFamily.DECLARATION_SHAPE,
                                classes=classes,
                                functions=functions,
                            )
                        )
        elif isinstance(search, PadShapeSearch):
            for classes in search.classes.values():
                for functions_per_class in search.functions_per_class.values():
                    add(
                        _state(
                            DeclarationFamily.PAD_SHAPE,
                            classes=classes,
                            functions_per_class=functions_per_class,
                        )
                    )
        elif isinstance(search, ForwardDeclarationSearch):
            for placement in search.placements:
                for count in search.counts.values():
                    add(
                        _state(
                            DeclarationFamily.FORWARD_DECLARATION_RUN,
                            count=count,
                            placement=placement.value,
                            prefix=search.prefix,
                            width=search.width,
                        )
                    )
        else:
            assert isinstance(search, ExternRunPairSearch)
            for header_count in search.header_counts.values():
                for seat_count in search.seat_counts.values():
                    if header_count == 0 and seat_count == 0:
                        continue
                    add(
                        _state(
                            DeclarationFamily.EXTERN_RUN_PAIR,
                            header_count=header_count,
                            header_prefix=search.header_prefix,
                            seat_count=seat_count,
                            seat_prefix=search.seat_prefix,
                            width=search.width,
                        )
                    )

    states.sort(key=lambda item: canonical_json(item))
    if not states:
        raise DiscoveryError("declaration campaign enumerates no legal states")
    return tuple(states)


class CompileReceipt(StrictModel):
    compiler_context: Digest
    command: Digest
    working_directory: Annotated[str, Field(min_length=1, max_length=8192)]
    pdb: Digest | None = None
    pdb_size: Annotated[int, Field(ge=0)] | None = None

    @model_validator(mode="after")
    def complete_pdb_receipt(self) -> CompileReceipt:
        if (self.pdb is None) != (self.pdb_size is None):
            raise ValueError("PDB digest and size must be present together")
        return self


class FunctionObservation(StrictModel):
    symbol: Annotated[str, Field(min_length=1, max_length=2048)]
    section_number: Annotated[int, Field(gt=0)]
    section_offset: Annotated[int, Field(ge=0)]
    body_size: Annotated[int, Field(gt=0)]
    body: Digest
    relocation_count: Annotated[int, Field(ge=0)]
    relocations: Digest
    line_count: Annotated[int, Field(ge=0)]
    metadata: Digest
    comdat_selection: Annotated[int, Field(ge=0, le=255)]


class CellObservation(StrictModel):
    cell_id: Identifier
    state_id: Identifier
    state: DeclarationState
    object: Digest
    compile: CompileReceipt
    functions: tuple[FunctionObservation, ...]

    @model_validator(mode="after")
    def canonical_functions(self) -> CellObservation:
        keys = tuple(
            (item.symbol.casefold(), item.section_number, item.section_offset)
            for item in self.functions
        )
        if keys != tuple(sorted(set(keys))):
            raise ValueError("observed functions must be unique and canonical")
        if self.state_id != declaration_state_id(self.state):
            raise ValueError("cell state identifier differs from its declaration state")
        return self


class MosaicRangeProposal(StrictModel):
    donor_cell_id: Identifier
    offset: Annotated[int, Field(ge=0)]
    length: Annotated[int, Field(gt=0, le=64)]
    seed: Digest
    donor: Digest
    seed_instruction_lengths: Annotated[tuple[int, ...], Field(min_length=1, max_length=64)]
    donor_instruction_lengths: Annotated[
        tuple[int, ...], Field(min_length=1, max_length=64)
    ]

    @model_validator(mode="after")
    def instruction_partitions(self) -> MosaicRangeProposal:
        if (
            any(not 1 <= item <= 15 for item in self.seed_instruction_lengths)
            or any(not 1 <= item <= 15 for item in self.donor_instruction_lengths)
            or sum(self.seed_instruction_lengths) != self.length
            or sum(self.donor_instruction_lengths) != self.length
        ):
            raise ValueError("mosaic instruction lengths do not partition their range")
        if self.seed == self.donor:
            raise ValueError("mosaic range does not change compiler output")
        return self


class DiscoveryArtifactRole(StrEnum):
    STATE_CARRIER = "state_carrier"
    PRIVATE_DONOR = "private_donor"
    MOSAIC_SEED = "mosaic_seed"
    MOSAIC_DONOR = "mosaic_donor"


class DiscoveryInputRole(StrEnum):
    REQUEST = "request"
    SOURCE = "source"
    REFERENCE = "reference"
    SEED = "seed"


class DiscoveryInputReceipt(StrictModel):
    """One readable CLI input receipt retained in the report."""

    role: DiscoveryInputRole
    logical_path: Annotated[str, Field(min_length=1, max_length=8192)]
    digest: Digest
    size: Annotated[int, Field(ge=0)]
    symbol: Annotated[str, Field(min_length=1, max_length=2048)] | None = None

    @field_validator("logical_path")
    @classmethod
    def canonical_relative_path(cls, value: str) -> str:
        if "\0" in value or "\\" in value:
            raise ValueError("discovery input path must be canonical POSIX relative text")
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or path.as_posix() != value
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("discovery input path must be canonical POSIX relative text")
        return value

    @model_validator(mode="after")
    def symbol_role(self) -> DiscoveryInputReceipt:
        if (self.role in {DiscoveryInputRole.REFERENCE, DiscoveryInputRole.SEED}) != (
            self.symbol is not None
        ):
            raise ValueError("only reference and seed inputs name a symbol")
        return self


class DiscoveryCompilerReceipt(StrictModel):
    """Readable invariant compiler configuration shared by campaign cells."""

    identity: Annotated[str, Field(min_length=1, max_length=128)]
    executable: Annotated[str, Field(min_length=1, max_length=8192)]
    arguments: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=4096)], ...],
        Field(max_length=256),
    ]
    toolchain_authority: Digest

    @model_validator(mode="after")
    def safe_text(self) -> DiscoveryCompilerReceipt:
        if "\0" in self.executable or any("\0" in item for item in self.arguments):
            raise ValueError("compiler receipt text must be NUL-free")
        return self


class DiscoveryStateExport(StrictModel):
    """Exact declaration payload behind one selected compiler cell."""

    cell_id: Identifier
    state_id: Identifier
    state: DeclarationState
    generated_declarations: Annotated[str, Field(max_length=1024 * 1024)]
    generated_declarations_digest: Digest

    @model_validator(mode="after")
    def exact_state(self) -> DiscoveryStateExport:
        try:
            payload = self.generated_declarations.encode("ascii", "strict")
        except UnicodeEncodeError as exc:
            raise ValueError("generated declarations must be exact ASCII") from exc
        if self.state_id != declaration_state_id(self.state):
            raise ValueError("selected state identifier differs")
        if Digest.from_bytes(payload) != self.generated_declarations_digest:
            raise ValueError("generated declaration bytes differ from their digest")
        return self


class DiscoveryArtifactReceipt(StrictModel):
    """One selected object that a proposal can resolve and review."""

    artifact_id: Identifier
    role: DiscoveryArtifactRole
    symbol: Annotated[str, Field(min_length=1, max_length=2048)]
    logical_path: Annotated[str, Field(min_length=1, max_length=8192)]
    object: Digest
    object_size: Annotated[int, Field(gt=0)]
    cell_id: Identifier | None = None

    @field_validator("logical_path")
    @classmethod
    def canonical_relative_path(cls, value: str) -> str:
        if "\0" in value or "\\" in value:
            raise ValueError("artifact path must be canonical POSIX relative text")
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or path.as_posix() != value
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("artifact path must be canonical POSIX relative text")
        return value

    @model_validator(mode="after")
    def role_has_expected_source(self) -> DiscoveryArtifactReceipt:
        if (self.role is DiscoveryArtifactRole.MOSAIC_SEED) != (self.cell_id is None):
            raise ValueError("only mosaic seed artifacts may omit a compiler cell")
        return self


class DiscoveryProposal(StrictModel):
    """Reviewable, non-authoritative intervention data."""

    schema_version: Literal[1] = 1
    noncertifying: Literal[True] = True
    campaign_id: Identifier
    finding_id: Identifier
    kind: DiscoveryFindingKind
    scope: Scope
    symbol: Annotated[str, Field(min_length=1, max_length=2048)]
    state_ids: Annotated[tuple[Identifier, ...], Field(min_length=1)]
    reference_body: Digest
    proposed_output: Digest
    intervention: Intervention
    artifact_ids: Annotated[tuple[Identifier, ...], Field(min_length=1)]
    ranges: tuple[MosaicRangeProposal, ...] = ()
    rationale: Annotated[str, Field(min_length=32, max_length=4096)]

    @model_validator(mode="after")
    def canonical_proposal(self) -> DiscoveryProposal:
        if self.state_ids != tuple(sorted(set(self.state_ids))):
            raise ValueError("proposal states must be unique and canonical")
        if self.artifact_ids != tuple(sorted(set(self.artifact_ids))):
            raise ValueError("proposal artifacts must be unique and canonical")
        ordered = tuple(sorted(self.ranges, key=lambda item: item.offset))
        if ordered != self.ranges:
            raise ValueError("mosaic ranges must be in canonical order")
        for left, right in zip(self.ranges, self.ranges[1:], strict=False):
            if left.offset + left.length > right.offset:
                raise ValueError("mosaic ranges overlap")
        if self.kind is DiscoveryFindingKind.INSTRUCTION_MOSAIC:
            if not self.ranges:
                raise ValueError("instruction mosaic proposal has no ranges")
        elif self.ranges:
            raise ValueError("only instruction mosaic proposals may contain ranges")
        if self.intervention.scope != self.scope:
            raise ValueError("proposal intervention scope differs")
        return self


class DiscoveryCampaignReport(StrictModel):
    schema_version: Literal[1] = 1
    noncertifying: Literal[True] = True
    campaign_id: Identifier
    plan: DiscoveryPlan
    plan_digest: Digest
    compile_implementation_digest: Digest
    analysis_implementation_digest: Digest
    compile_authority_digest: Digest
    analysis_authority_digest: Digest
    adapter: Annotated[str, Field(min_length=1, max_length=128)]
    compiler: DiscoveryCompilerReceipt
    inputs: tuple[DiscoveryInputReceipt, ...]
    complete: Literal[True] = True
    cells_total: Annotated[int, Field(gt=0)]
    cells_built: Annotated[int, Field(ge=0)]
    cells_cached: Annotated[int, Field(ge=0)]
    observations: tuple[CellObservation, ...]
    proposals: tuple[DiscoveryProposal, ...]
    selected_states: tuple[DiscoveryStateExport, ...]
    artifacts: tuple[DiscoveryArtifactReceipt, ...]

    @model_validator(mode="after")
    def complete_accounting(self) -> DiscoveryCampaignReport:
        if self.cells_built + self.cells_cached != self.cells_total:
            raise ValueError("discovery cell accounting is incomplete")
        if len(self.observations) != self.cells_total:
            raise ValueError("discovery report omits cell observations")
        if (
            sum(len(item.functions) for item in self.observations)
            > self.plan.max_observed_functions
        ):
            raise ValueError("discovery report exceeds its observed-function limit")
        cells = tuple(item.cell_id for item in self.observations)
        if cells != tuple(sorted(set(cells))):
            raise ValueError("discovery observations must be unique and canonical")
        findings = tuple(item.finding_id for item in self.proposals)
        if findings != tuple(sorted(set(findings))):
            raise ValueError("discovery proposals must be unique and canonical")
        if any(item.campaign_id != self.campaign_id for item in self.proposals):
            raise ValueError("discovery proposal belongs to another campaign")
        input_keys = tuple(
            (item.role.value, item.symbol or "", item.logical_path) for item in self.inputs
        )
        if input_keys != tuple(sorted(set(input_keys))):
            raise ValueError("discovery input receipts must be unique and canonical")
        selected_cells = tuple(item.cell_id for item in self.selected_states)
        if selected_cells != tuple(sorted(set(selected_cells))):
            raise ValueError("selected discovery states must be unique and canonical")
        selected_state_ids = tuple(item.state_id for item in self.selected_states)
        proposed_state_ids = tuple(
            sorted({state_id for proposal in self.proposals for state_id in proposal.state_ids})
        )
        if tuple(sorted(selected_state_ids)) != proposed_state_ids:
            raise ValueError("selected state exports differ from proposal states")
        artifact_ids = tuple(item.artifact_id for item in self.artifacts)
        if artifact_ids != tuple(sorted(set(artifact_ids))):
            raise ValueError("discovery artifacts must be unique and canonical")
        proposed_artifacts = tuple(
            sorted(
                {
                    artifact_id
                    for proposal in self.proposals
                    for artifact_id in proposal.artifact_ids
                }
            )
        )
        if artifact_ids != proposed_artifacts:
            raise ValueError("artifact exports differ from proposal references")
        selected_cell_set = set(selected_cells)
        if any(
            item.cell_id is not None and item.cell_id not in selected_cell_set
            for item in self.artifacts
        ):
            raise ValueError("artifact names an unexported discovery state")
        return self


def discovery_report_json_schema() -> JsonValue:
    """Return the self-contained schema for non-certifying discovery reports."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:reprobit:schema:discovery-report:1",
        **DiscoveryCampaignReport.model_json_schema(
            mode="validation",
            ref_template="#/$defs/{model}",
        ),
    }


@dataclass(frozen=True, slots=True)
class DiscoveryCompileOutput:
    object_path: Path
    receipt: CompileReceipt
    metadata: Mapping[str, JsonValue] = MappingProxyType({})


@dataclass(frozen=True, slots=True)
class DiscoveryProduct:
    state: DeclarationState
    object_path: Path
    observation: CellObservation


@dataclass(frozen=True, slots=True)
class DiscoveryArtifactPayload:
    """Adapter-selected bytes handed to the runner's immutable artifact store."""

    artifact_id: str
    role: DiscoveryArtifactRole
    symbol: str
    object_bytes: bytes
    cell_id: str | None = None
    state: DeclarationState | None = None
    generated_declarations: bytes | None = None


class DiscoveryAdapter(Protocol):
    """Compiler-specific implementation behind the durable campaign runner."""

    @property
    def identity(self) -> str: ...

    @property
    def maximum_parallelism(self) -> int: ...

    def compile_implementation_digest(self) -> Digest: ...

    def analysis_implementation_digest(self) -> Digest: ...

    def compiler_receipt(self) -> DiscoveryCompilerReceipt: ...

    def compile_authority_digest(self) -> Digest: ...

    def revalidate_compile_authority(self, expected: Digest) -> None: ...

    def analysis_authority_digest(self, compile_authority: Digest) -> Digest: ...

    def cache_material(self, state: DeclarationState) -> Mapping[str, JsonValue]: ...

    def compile(
        self,
        state: DeclarationState,
        workspace: Path,
        cancellation: CancellationToken,
    ) -> DiscoveryCompileOutput: ...

    def observe(
        self,
        *,
        cell_id: str,
        state: DeclarationState,
        object_path: Path,
        receipt: CompileReceipt,
    ) -> CellObservation: ...

    def analyze(
        self,
        *,
        campaign_id: str,
        plan: DiscoveryPlan,
        products: Sequence[DiscoveryProduct],
    ) -> tuple[DiscoveryProposal, ...]: ...

    def proposal_artifacts(
        self,
        *,
        campaign_id: str,
        proposals: Sequence[DiscoveryProposal],
        products: Sequence[DiscoveryProduct],
    ) -> tuple[DiscoveryArtifactPayload, ...]: ...

__all__ = [
    "CellObservation",
    "CompileReceipt",
    "DeclarationFamily",
    "DeclarationParameter",
    "DeclarationPlacement",
    "DeclarationSearch",
    "DeclarationShapeSearch",
    "DeclarationState",
    "DiscoveryAdapter",
    "DiscoveryArtifactPayload",
    "DiscoveryArtifactReceipt",
    "DiscoveryArtifactRole",
    "DiscoveryCampaignReport",
    "DiscoveryCompileOutput",
    "DiscoveryCompilerReceipt",
    "DiscoveryError",
    "DiscoveryFindingKind",
    "DiscoveryInputReceipt",
    "DiscoveryInputRole",
    "DiscoveryPlan",
    "DiscoveryProduct",
    "DiscoveryProposal",
    "DiscoveryStateExport",
    "ExternRunPairSearch",
    "ForwardDeclarationSearch",
    "FunctionObservation",
    "InclusiveRange",
    "MosaicLimits",
    "MosaicRangeProposal",
    "PadShapeSearch",
    "declaration_state_id",
    "discovery_report_json_schema",
    "enumerate_declaration_states",
]
