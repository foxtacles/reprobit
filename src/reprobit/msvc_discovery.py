"""MSVC request and compiler adapter for bounded intervention discovery.

The adapter composes the reusable direct compiler with the bounded COFF
analysis module; neither depends on project-specific setup code.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Any, Literal, cast

from pydantic import Field, model_validator

from reprobit.discovery_contracts import (
    CellObservation,
    CompileReceipt,
    DeclarationState,
    DiscoveryArtifactPayload,
    DiscoveryCompileOutput,
    DiscoveryCompilerReceipt,
    DiscoveryError,
    DiscoveryPlan,
    DiscoveryProduct,
    DiscoveryProposal,
)
from reprobit.implementation import scoped_package_implementation_digest
from reprobit.model import Digest, StrictModel
from reprobit.msvc_compile import (
    MsvcStateCompiler,
    render_msvc_declaration_state,
    safe_msvc_compiler_arguments,
    validate_msvc_compiler_arguments,
)
from reprobit.msvc_discovery_analysis import (
    analyze_msvc_discovery_products,
    msvc_analysis_authority_digest,
    msvc_discovery_analysis_implementation_digest,
)
from reprobit.msvc_discovery_coff import (
    MsvcFunctionReference,
    observe_msvc_discovery_object,
)
from reprobit.msvc_discovery_proposals import build_msvc_discovery_artifacts
from reprobit.process import CancellationToken
from reprobit.secure_path_contracts import SecurePathError, canonical_relative_path
from reprobit.strict_json import JsonValue, canonical_json

_CANONICAL_RELATIVE_PATH_PATTERN = (
    r"^(?!/)(?!.*\\)(?!.*\x00)(?!.*(?:^|/)(?:\.|\.\.)(?:/|$))"
    r"[^/]+(?:/[^/]+)*$"
)
_COMPILE_IMPLEMENTATION_PATHS = (
    "cache.py",
    "declaration_shapes.py",
    "discovery.py",
    "discovery_contracts.py",
    "implementation.py",
    "model.py",
    "msvc_compile.py",
    "msvc_discovery.py",
    "process.py",
    "secure_path_contracts.py",
    "secure_paths.py",
    "secure_paths_posix.py",
    "secure_paths_windows.py",
    "strict_json.py",
)


def _relative_input_path(value: str, label: str) -> str:
    try:
        canonical_relative_path(value)
    except SecurePathError:
        raise ValueError(f"{label} must be a canonical POSIX relative path") from None
    return value


class MsvcDiscoveryObjectInput(StrictModel):
    """One same-symbol object input resolved relative to the request file."""

    symbol: Annotated[str, Field(min_length=1, max_length=2048)]
    object: Annotated[str, Field(min_length=1, max_length=4096)]

    @model_validator(mode="after")
    def canonical_path(self) -> MsvcDiscoveryObjectInput:
        _relative_input_path(self.object, "discovery object")
        return self


class MsvcDiscoveryRequest(StrictModel):
    """Portable preview request; host toolchain and state paths stay in CLI flags."""

    schema_version: Literal[1] = 1
    source: Annotated[str, Field(min_length=1, max_length=4096)]
    plan: DiscoveryPlan
    references: Annotated[tuple[MsvcDiscoveryObjectInput, ...], Field(min_length=1, max_length=256)]
    seeds: Annotated[tuple[MsvcDiscoveryObjectInput, ...], Field(max_length=256)] = ()
    compiler_arguments: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=4096)], ...],
        Field(min_length=1, max_length=256),
    ]

    @model_validator(mode="after")
    def canonical_inputs(self) -> MsvcDiscoveryRequest:
        _relative_input_path(self.source, "discovery source")
        reference_symbols = tuple(item.symbol for item in self.references)
        seed_symbols = tuple(item.symbol for item in self.seeds)
        if reference_symbols != tuple(sorted(set(reference_symbols), key=str.casefold)):
            raise ValueError("discovery references must be unique and canonical")
        if seed_symbols != tuple(sorted(set(seed_symbols), key=str.casefold)):
            raise ValueError("discovery seeds must be unique and canonical")
        if not set(seed_symbols).issubset(reference_symbols):
            raise ValueError("every discovery seed must have a sealed reference")
        if self.plan.symbols and not set(self.plan.symbols).issubset(reference_symbols):
            raise ValueError("every planned symbol must have a sealed reference")
        if any("\0" in item for item in self.compiler_arguments):
            raise ValueError("compiler arguments must be NUL-free")
        try:
            validate_msvc_compiler_arguments(self.compiler_arguments)
        except DiscoveryError as exc:
            raise ValueError(str(exc)) from exc
        return self


def msvc_discovery_request_json_schema() -> JsonValue:
    """Return the structural schema plus documented canonical runtime rules."""

    generated = MsvcDiscoveryRequest.model_json_schema(
        mode="validation",
        ref_template="#/$defs/{model}",
    )
    definitions = cast(dict[str, Any], generated["$defs"])
    inclusive = cast(dict[str, Any], definitions["InclusiveRange"])

    def bounded_range(name: str, minimum: int, maximum: int) -> None:
        model = deepcopy(inclusive)
        model["title"] = name
        properties = cast(dict[str, Any], model["properties"])
        for endpoint in ("start", "stop"):
            properties[endpoint]["minimum"] = minimum
            properties[endpoint]["maximum"] = maximum
        definitions[name] = model

    bounded_range("Range1To10", 1, 10)
    bounded_range("Range1To99", 1, 99)
    bounded_range("Range1To100", 1, 100)
    bounded_range("Range1To999", 1, 999)
    bounded_range("Range0To999", 0, 999)
    search_ranges = {
        "DeclarationShapeSearch": {
            "classes": "Range1To10",
            "functions": "Range1To100",
        },
        "PadShapeSearch": {
            "classes": "Range1To99",
            "functions_per_class": "Range1To99",
        },
        "ForwardDeclarationSearch": {"counts": "Range1To999"},
        "ExternRunPairSearch": {
            "header_counts": "Range0To999",
            "seat_counts": "Range0To999",
        },
    }
    for model_name, fields in search_ranges.items():
        model = cast(dict[str, Any], definitions[model_name])
        required = set(cast(list[str], model.get("required", [])))
        required.add("family")
        model["required"] = sorted(required)
        properties = cast(dict[str, Any], model["properties"])
        for field_name, range_name in fields.items():
            properties[field_name] = {"$ref": f"#/$defs/{range_name}"}

    width_limits = ((1, 10), (2, 100), (3, 999))
    forward = cast(dict[str, Any], definitions["ForwardDeclarationSearch"])
    forward["allOf"] = [
        {
            "if": {"properties": {"width": {"const": width}}, "required": ["width"]},
            "then": {
                "properties": {
                    "counts": {
                        "properties": {
                            "start": {"maximum": maximum},
                            "stop": {"maximum": maximum},
                        }
                    }
                }
            },
        }
        for width, maximum in width_limits
    ]
    extern = cast(dict[str, Any], definitions["ExternRunPairSearch"])
    extern["allOf"] = [
        {
            "if": {"properties": {"width": {"const": width}}, "required": ["width"]},
            "then": {
                "properties": {
                    field_name: {
                        "properties": {
                            "start": {"maximum": maximum},
                            "stop": {"maximum": maximum},
                        }
                    }
                    for field_name in ("header_counts", "seat_counts")
                }
            },
        }
        for width, maximum in width_limits
    ]
    object_input = cast(dict[str, Any], definitions["MsvcDiscoveryObjectInput"])
    cast(dict[str, Any], object_input["properties"])["object"]["pattern"] = (
        _CANONICAL_RELATIVE_PATH_PATTERN
    )
    root_properties = cast(dict[str, Any], generated["properties"])
    root_properties["source"]["pattern"] = _CANONICAL_RELATIVE_PATH_PATTERN
    root_properties["compiler_arguments"]["items"] = {
        "enum": list(safe_msvc_compiler_arguments()),
        "type": "string",
    }
    for field_name in ("references", "seeds"):
        root_properties[field_name]["uniqueItems"] = True
        root_properties[field_name]["description"] = (
            "Entries must also be unique and sorted by case-folded symbol; seed "
            "symbols must be a subset of references."
        )
    plan = cast(dict[str, Any], definitions["DiscoveryPlan"])
    plan_properties = cast(dict[str, Any], plan["properties"])
    plan_properties["symbols"]["uniqueItems"] = True
    plan_properties["symbols"]["description"] = (
        "Symbols must also be unique and sorted by case-folded spelling."
    )
    forward_properties = cast(dict[str, Any], forward["properties"])
    forward_properties["placements"]["uniqueItems"] = True
    forward_properties["placements"]["description"] = (
        "Placements must also be in canonical lexical order."
    )
    generated["$comment"] = (
        "JSON Schema cannot express case-folded ordering, prefix inequality, symbol "
        "subset relationships, or the exact expanded max_cells count. The CLI "
        "enforces those cross-field rules before starting a compiler."
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:reprobit:schema:msvc-discovery-request:1",
        **generated,
    }


class MsvcDiscoveryAdapter:
    """Render declaration cells, index every function, and qualify proposals."""

    def __init__(
        self,
        *,
        source: bytes,
        compiler: MsvcStateCompiler,
        references: Sequence[MsvcFunctionReference],
        seed_objects: Mapping[str, bytes] | None = None,
    ) -> None:
        if not references:
            raise DiscoveryError("MSVC discovery requires at least one function reference")
        reference_map = {item.symbol: item for item in references}
        if len(reference_map) != len(references):
            raise DiscoveryError("MSVC discovery reference symbols must be unique")
        seeds = dict(seed_objects or {})
        if any(not symbol or not payload for symbol, payload in seeds.items()):
            raise DiscoveryError("MSVC discovery seed objects are malformed")
        self.source = bytes(source)
        self.compiler = compiler
        self.references = MappingProxyType(
            dict(sorted(reference_map.items(), key=lambda item: item[0].casefold()))
        )
        self.seed_objects = MappingProxyType(
            dict(sorted(seeds.items(), key=lambda item: item[0].casefold()))
        )

    @property
    def identity(self) -> str:
        return f"msvc-coff-discovery-v1:{self.compiler.identity}"

    @property
    def maximum_parallelism(self) -> int:
        return self.compiler.maximum_parallelism

    def compile_implementation_digest(self) -> Digest:
        return scoped_package_implementation_digest(_COMPILE_IMPLEMENTATION_PATHS)

    def analysis_implementation_digest(self) -> Digest:
        return msvc_discovery_analysis_implementation_digest()

    def compiler_receipt(self) -> DiscoveryCompilerReceipt:
        return self.compiler.compiler_receipt()

    def compile_authority_digest(self) -> Digest:
        return Digest.from_bytes(
            canonical_json(
                {
                    "schema_version": 1,
                    "compiler": self.compiler.pinned_authority_digest(),
                    "source": Digest.from_bytes(self.source),
                }
            )
        )

    def revalidate_compile_authority(self, expected: Digest) -> None:
        self.compiler.revalidate_authority(self.compiler.pinned_authority_digest())
        if self.compile_authority_digest() != expected:
            raise DiscoveryError("MSVC discovery compile authority changed")

    def analysis_authority_digest(self, compile_authority: Digest) -> Digest:
        return msvc_analysis_authority_digest(
            compile_authority=compile_authority,
            references=self.references,
            seed_objects=self.seed_objects,
        )

    def cache_material(self, state: DeclarationState) -> Mapping[str, JsonValue]:
        rendered = render_msvc_declaration_state(self.source, state)
        return {
            "rendered_source": cast(
                JsonValue,
                Digest.from_bytes(rendered.source).model_dump(mode="json"),
            ),
            "force_include": cast(
                JsonValue,
                (
                    Digest.from_bytes(rendered.force_include).model_dump(mode="json")
                    if rendered.force_include is not None
                    else None
                ),
            ),
            "generated_declarations": cast(
                JsonValue,
                Digest.from_bytes(rendered.generated_declarations).model_dump(mode="json"),
            ),
        }

    def compile(
        self,
        state: DeclarationState,
        workspace: Path,
        cancellation: CancellationToken,
    ) -> DiscoveryCompileOutput:
        return self.compiler.compile(
            render_msvc_declaration_state(self.source, state),
            workspace,
            cancellation,
        )

    def observe(
        self,
        *,
        cell_id: str,
        state: DeclarationState,
        object_path: Path,
        receipt: CompileReceipt,
    ) -> CellObservation:
        return observe_msvc_discovery_object(
            cell_id=cell_id,
            state=state,
            object_path=object_path,
            receipt=receipt,
        )

    def proposal_artifacts(
        self,
        *,
        campaign_id: str,
        proposals: Sequence[DiscoveryProposal],
        products: Sequence[DiscoveryProduct],
    ) -> tuple[DiscoveryArtifactPayload, ...]:
        return build_msvc_discovery_artifacts(
            source=self.source,
            seed_objects=self.seed_objects,
            campaign_id=campaign_id,
            proposals=proposals,
            products=products,
        )

    def analyze(
        self,
        *,
        campaign_id: str,
        plan: DiscoveryPlan,
        products: Sequence[DiscoveryProduct],
    ) -> tuple[DiscoveryProposal, ...]:
        return analyze_msvc_discovery_products(
            references=self.references,
            seed_objects=self.seed_objects,
            campaign_id=campaign_id,
            plan=plan,
            products=products,
        )


__all__ = [
    "MsvcDiscoveryAdapter",
    "MsvcDiscoveryObjectInput",
    "MsvcDiscoveryRequest",
    "msvc_discovery_request_json_schema",
]
