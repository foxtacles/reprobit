from __future__ import annotations

import hashlib
import os
import re
import struct
import sys
import time
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from pydantic import ValidationError

import reprobit.msvc_discovery as msvc_discovery
import reprobit.msvc_discovery_analysis as msvc_discovery_analysis
from reprobit.coff import CoffObject
from reprobit.discovery_contracts import (
    CompileReceipt,
    DeclarationFamily,
    DeclarationParameter,
    DeclarationPlacement,
    DeclarationState,
    DiscoveryCompileOutput,
    DiscoveryCompilerReceipt,
    DiscoveryError,
    DiscoveryFindingKind,
    DiscoveryPlan,
    DiscoveryProduct,
    ForwardDeclarationSearch,
    InclusiveRange,
    declaration_state_id,
    enumerate_declaration_states,
)
from reprobit.model import Digest
from reprobit.msvc_compile import (
    DirectMsvcCompiler,
    RenderedMsvcState,
    render_msvc_declaration_state,
)
from reprobit.msvc_discovery import (
    MsvcDiscoveryAdapter,
    MsvcDiscoveryObjectInput,
    MsvcDiscoveryRequest,
    msvc_discovery_request_json_schema,
)
from reprobit.msvc_discovery_analysis import (
    MsvcFunctionReference,
    qualify_msvc_reference_object,
)
from reprobit.process import CancellationToken, ProcessCancelled
from reprobit.strict_json import JsonValue

TARGET = "?Transform@Widget@@QAEHH@Z"
HELPER = "?Clamp@Widget@@SAHH@Z"


def _state(family: DeclarationFamily, **parameters: int | str) -> DeclarationState:
    return DeclarationState(
        family=family,
        parameters=tuple(
            DeclarationParameter(name=name, value=value)
            for name, value in sorted(parameters.items())
        ),
    )


def _section_aux(length: int, selection: int, *, associated: int = 0) -> bytes:
    payload = bytearray(18)
    struct.pack_into("<I", payload, 0, length)
    struct.pack_into("<I", payload, 8, 0xA5A5A5A5)
    struct.pack_into("<H", payload, 12, associated)
    payload[14] = selection
    return bytes(payload)


def _coff(
    functions: list[tuple[str, bytes]],
    *,
    associated_body: bytes | None = None,
) -> bytes:
    """Build a neutral i386 COFF with one isolated COMDAT per function."""

    section_count = len(functions) + int(associated_body is not None)
    cursor = 20 + section_count * 40
    payload = bytearray()
    sections: list[tuple[int, bytes]] = []
    for _symbol, body in functions:
        sections.append((cursor, body))
        payload.extend(body)
        cursor += len(body)
    associated_offset: int | None = None
    if associated_body is not None:
        associated_offset = cursor
        payload.extend(associated_body)
        cursor += len(associated_body)

    strings = bytearray(b"\0\0\0\0")
    string_offsets: dict[str, int] = {}

    def encoded(name: str) -> bytes:
        raw = name.encode("ascii")
        if len(raw) <= 8:
            return raw.ljust(8, b"\0")
        offset = string_offsets.get(name)
        if offset is None:
            offset = len(strings)
            string_offsets[name] = offset
            strings.extend(raw + b"\0")
        return b"\0\0\0\0" + struct.pack("<I", offset)

    symbols = bytearray()
    symbol_count = 0
    for section_number, (symbol, body) in enumerate(functions, start=1):
        symbols.extend(
            encoded(".text")
            + struct.pack("<IhHBB", 0, section_number, 0, 3, 1)
            + _section_aux(len(body), 2)
        )
        symbol_count += 2
        symbols.extend(
            encoded(symbol) + struct.pack("<IhHBB", 0, section_number, 0x20, 2, 0)
        )
        symbol_count += 1
    if associated_body is not None:
        symbols.extend(
            encoded(".debug$S")
            + struct.pack("<IhHBB", 0, section_count, 0, 3, 1)
            + _section_aux(len(associated_body), 5, associated=1)
        )
        symbol_count += 2

    struct.pack_into("<I", strings, 0, len(strings))
    headers = bytearray()
    for raw_offset, body in sections:
        headers.extend(b".text\0\0\0")
        headers.extend(
            struct.pack(
                "<IIIIIIHHI",
                0,
                0,
                len(body),
                raw_offset,
                0,
                0,
                0,
                0,
                0x60501020,
            )
        )
    if associated_body is not None:
        assert associated_offset is not None
        headers.extend(b".debug$S")
        headers.extend(
            struct.pack(
                "<IIIIIIHHI",
                0,
                0,
                len(associated_body),
                associated_offset,
                0,
                0,
                0,
                0,
                0x42301040,
            )
        )
    header = struct.pack(
        "<HHIIIHH",
        0x14C,
        section_count,
        0x12345678,
        cursor,
        symbol_count,
        0,
        0,
    )
    return bytes(header + headers + payload + symbols + strings)


def _with_primary_relocation(payload: bytes, relocation_type: int) -> bytes:
    """Add one self-relocation to the first COMDAT in a neutral test object."""

    coff = CoffObject(payload)
    section = coff.sections[0]
    assert section["raw_size"] >= 5
    old_symbol_offset = coff.symbol_offset
    new_symbol_offset = old_symbol_offset + 10
    result = bytearray(payload)
    result[old_symbol_offset:old_symbol_offset] = struct.pack(
        "<IIH",
        1,
        2,
        relocation_type,
    )
    struct.pack_into("<I", result, 8, new_symbol_offset)
    struct.pack_into("<I", result, section["header_offset"] + 24, old_symbol_offset)
    struct.pack_into("<H", result, section["header_offset"] + 32, 1)
    struct.pack_into("<H", result, new_symbol_offset + 18 + 4, 1)
    return bytes(result)


class _NeverCompiler:
    identity = "neutral-test-msvc"
    maximum_parallelism = 1

    def pinned_authority_digest(self) -> Digest:
        return Digest.from_bytes(b"neutral test compiler")

    def revalidate_authority(self, expected: Digest) -> None:
        assert expected == self.pinned_authority_digest()

    def compiler_receipt(self) -> DiscoveryCompilerReceipt:
        return DiscoveryCompilerReceipt(
            identity=self.identity,
            executable="/neutral/test-compiler",
            arguments=("/nologo",),
            toolchain_authority=self.pinned_authority_digest(),
        )

    def compile(
        self,
        rendered: RenderedMsvcState,
        workspace: Path,
        cancellation: CancellationToken | None = None,
    ) -> DiscoveryCompileOutput:
        del rendered, workspace, cancellation
        raise AssertionError("analysis unit tests do not compile")


def _receipt() -> CompileReceipt:
    return CompileReceipt(
        compiler_context=Digest.from_bytes(b"compiler"),
        command=Digest.from_bytes(b"command"),
        working_directory="/neutral/discovery/workspace",
    )


def _plan(count: int) -> DiscoveryPlan:
    return DiscoveryPlan(
        target="neutral",
        translation_unit="widget",
        symbols=(TARGET,),
        searches=(
            ForwardDeclarationSearch(
                family=DeclarationFamily.FORWARD_DECLARATION_RUN,
                prefix="Carrier",
                counts=InclusiveRange(start=1, stop=count),
                width=1,
                placements=(DeclarationPlacement.FORCE_INCLUDE,),
            ),
        ),
        max_cells=count,
    )


def _product(
    adapter: MsvcDiscoveryAdapter,
    state: DeclarationState,
    path: Path,
    payload: bytes,
) -> DiscoveryProduct:
    path.write_bytes(payload)
    material = payload + declaration_state_id(state).encode()
    cell_id = f"cell.{hashlib.sha256(material).hexdigest()[:24]}"
    observation = adapter.observe(
        cell_id=cell_id,
        state=state,
        object_path=path,
        receipt=_receipt(),
    )
    return DiscoveryProduct(state, path, observation)


def test_renderer_covers_all_four_closed_families() -> None:
    source = b"#include <stddef.h>\nint Transform(int value);\n"
    shape = render_msvc_declaration_state(
        source,
        _state(DeclarationFamily.DECLARATION_SHAPE, classes=1, functions=1),
    )
    pad = render_msvc_declaration_state(
        source,
        _state(DeclarationFamily.PAD_SHAPE, classes=1, functions_per_class=1),
    )
    forward = render_msvc_declaration_state(
        source,
        _state(
            DeclarationFamily.FORWARD_DECLARATION_RUN,
            count=2,
            placement=DeclarationPlacement.AFTER_INCLUDES.value,
            prefix="Carrier",
            width=1,
        ),
    )
    extern = render_msvc_declaration_state(
        source,
        _state(
            DeclarationFamily.EXTERN_RUN_PAIR,
            header_count=1,
            header_prefix="gHeader_",
            seat_count=1,
            seat_prefix="gSeat_",
            width=1,
        ),
    )

    assert shape.source == source and shape.force_include is not None
    assert pad.source == source and pad.force_include is not None
    include_end = source.index(b"\n") + 1
    assert forward.source.startswith(source[:include_end] + b"class Carrier0;")
    assert forward.force_include is None
    assert extern.force_include == b"extern int gHeader_0;\n"
    assert extern.source.endswith(b"extern int gSeat_0;\n")


def test_renderer_fails_closed_on_missing_anchor_and_identifier_collision() -> None:
    after_includes = _state(
        DeclarationFamily.FORWARD_DECLARATION_RUN,
        count=1,
        placement=DeclarationPlacement.AFTER_INCLUDES.value,
        prefix="Carrier",
        width=1,
    )
    collision = _state(
        DeclarationFamily.FORWARD_DECLARATION_RUN,
        count=1,
        placement=DeclarationPlacement.PREFIX.value,
        prefix="Widget",
        width=1,
    )
    with pytest.raises(DiscoveryError, match="requires an include"):
        render_msvc_declaration_state(b"int value;\n", after_includes)
    with pytest.raises(DiscoveryError, match="collide"):
        render_msvc_declaration_state(b"class Widget0;\n", collision)


def test_observation_indexes_every_emitted_function(tmp_path: Path) -> None:
    reference_object = _coff([(TARGET, bytes.fromhex("b801000000c3"))])
    adapter = MsvcDiscoveryAdapter(
        source=b"int neutral;\n",
        compiler=_NeverCompiler(),
        references=(MsvcFunctionReference.from_object(reference_object, TARGET),),
    )
    state = enumerate_declaration_states(_plan(1))[0]
    candidate = _coff(
        [
            (TARGET, bytes.fromhex("b801000000c3")),
            (HELPER, bytes.fromhex("33c0c3")),
        ]
    )
    product = _product(adapter, state, tmp_path / "candidate.obj", candidate)

    assert tuple(item.symbol for item in product.observation.functions) == (HELPER, TARGET)
    assert all(item.section_offset == 0 for item in product.observation.functions)
    assert all(item.comdat_selection == 2 for item in product.observation.functions)


def test_exact_candidate_yields_validated_whole_and_private_donor_proposals(
    tmp_path: Path,
) -> None:
    seed = _coff([(TARGET, bytes.fromhex("b801000000c3"))])
    exact = _coff([(TARGET, bytes.fromhex("b802000000c3"))])
    adapter = MsvcDiscoveryAdapter(
        source=b"int neutral;\n",
        compiler=_NeverCompiler(),
        references=(MsvcFunctionReference.from_object(exact, TARGET),),
        seed_objects={TARGET: seed},
    )
    plan = _plan(1)
    state = enumerate_declaration_states(plan)[0]
    product = _product(adapter, state, tmp_path / "exact.obj", exact)

    proposals = adapter.analyze(
        campaign_id="campaign.neutral",
        plan=plan,
        products=(product,),
    )

    assert {item.kind for item in proposals} == {
        DiscoveryFindingKind.WHOLE_BODY,
        DiscoveryFindingKind.PRIVATE_DONOR,
    }
    whole = next(item for item in proposals if item.kind is DiscoveryFindingKind.WHOLE_BODY)
    private = next(
        item for item in proposals if item.kind is DiscoveryFindingKind.PRIVATE_DONOR
    )
    assert whole.scope.function is None
    assert private.scope.function == TARGET
    assert whole.intervention.kind == "state_carrier"
    assert private.intervention.kind == "equal_body_donor"
    artifacts = adapter.proposal_artifacts(
        campaign_id="campaign.neutral",
        proposals=proposals,
        products=(product,),
    )
    assert {item.artifact_id for item in artifacts} == {
        artifact_id for proposal in proposals for artifact_id in proposal.artifact_ids
    }
    assert all(item.object_bytes == exact for item in artifacts)
    assert all(item.generated_declarations for item in artifacts)


def test_exact_body_with_different_associated_comdat_content_is_not_qualified(
    tmp_path: Path,
) -> None:
    body = bytes.fromhex("b802000000c3")
    reference = _coff([(TARGET, body)], associated_body=b"reference metadata")
    candidate = _coff([(TARGET, body)], associated_body=b"candidate metadata")
    adapter = MsvcDiscoveryAdapter(
        source=b"int neutral;\n",
        compiler=_NeverCompiler(),
        references=(MsvcFunctionReference.from_object(reference, TARGET),),
    )
    plan = _plan(1)
    state = enumerate_declaration_states(plan)[0]
    product = _product(adapter, state, tmp_path / "candidate.obj", candidate)

    assert (
        adapter.analyze(
            campaign_id="campaign.neutral",
            plan=plan,
            products=(product,),
        )
        == ()
    )


def test_project_qualification_accepts_retained_associated_content() -> None:
    body = bytes.fromhex("b802000000c3")
    reference = _coff([(TARGET, body)], associated_body=b"reference metadata")
    candidate = _coff([(TARGET, body)], associated_body=b"retained seed metadata")

    qualify_msvc_reference_object(
        reference_object=reference,
        candidate_object=candidate,
        symbol=TARGET,
    )


def test_project_qualification_still_rejects_changed_function_body() -> None:
    reference = _coff(
        [(TARGET, bytes.fromhex("b802000000c3"))],
        associated_body=b"reference metadata",
    )
    candidate = _coff(
        [(TARGET, bytes.fromhex("b803000000c3"))],
        associated_body=b"retained seed metadata",
    )

    with pytest.raises(DiscoveryError, match="body does not match reference"):
        qualify_msvc_reference_object(
            reference_object=reference,
            candidate_object=candidate,
            symbol=TARGET,
        )


def test_project_qualification_still_rejects_changed_relocation_semantics() -> None:
    body = bytes.fromhex("b800000000c3")
    reference = _with_primary_relocation(_coff([(TARGET, body)]), 6)
    candidate = _with_primary_relocation(_coff([(TARGET, body)]), 20)

    with pytest.raises(DiscoveryError, match="incompatible relocations"):
        qualify_msvc_reference_object(
            reference_object=reference,
            candidate_object=candidate,
            symbol=TARGET,
        )


def test_two_donor_mosaic_is_bounded_and_reproduces_reference(tmp_path: Path) -> None:
    seed_body = bytes.fromhex("b801000000bb01000000c3")
    reference_body = bytes.fromhex("b802000000bb02000000c3")
    first_body = bytes.fromhex("b802000000bb01000000c3")
    second_body = bytes.fromhex("b801000000bb02000000c3")
    seed = _coff([(TARGET, seed_body)])
    reference_object = _coff([(TARGET, reference_body)])
    adapter = MsvcDiscoveryAdapter(
        source=b"int neutral;\n",
        compiler=_NeverCompiler(),
        references=(MsvcFunctionReference.from_object(reference_object, TARGET),),
        seed_objects={TARGET: seed},
    )
    plan = _plan(2)
    states = enumerate_declaration_states(plan)
    products = (
        _product(adapter, states[0], tmp_path / "first.obj", _coff([(TARGET, first_body)])),
        _product(
            adapter,
            states[1],
            tmp_path / "second.obj",
            _coff([(TARGET, second_body)]),
        ),
    )

    proposals = adapter.analyze(
        campaign_id="campaign.neutral",
        plan=plan,
        products=products,
    )

    assert len(proposals) == 1
    proposal = proposals[0]
    assert proposal.kind is DiscoveryFindingKind.INSTRUCTION_MOSAIC
    assert len(proposal.state_ids) == 2
    assert tuple((item.offset, item.length) for item in proposal.ranges) == ((0, 5), (5, 5))
    assert proposal.intervention.kind == "binary_surgery"
    assert proposal.proposed_output == Digest.from_bytes(reference_body)
    artifacts = adapter.proposal_artifacts(
        campaign_id="campaign.neutral",
        proposals=proposals,
        products=products,
    )
    assert {item.role.value for item in artifacts} == {"mosaic_seed", "mosaic_donor"}
    assert sum(item.role.value == "mosaic_seed" for item in artifacts) == 1


def test_mosaic_search_budget_fails_closed(tmp_path: Path) -> None:
    seed_body = bytes.fromhex("b801000000bb01000000c3")
    reference_body = bytes.fromhex("b802000000bb02000000c3")
    seed = _coff([(TARGET, seed_body)])
    reference_object = _coff([(TARGET, reference_body)])
    adapter = MsvcDiscoveryAdapter(
        source=b"int neutral;\n",
        compiler=_NeverCompiler(),
        references=(MsvcFunctionReference.from_object(reference_object, TARGET),),
        seed_objects={TARGET: seed},
    )
    raw_plan = _plan(2).model_dump(mode="python")
    raw_plan["mosaic"] = {
        "enabled": True,
        "max_donors": 2,
        "max_ranges": 8,
        "max_candidates_per_symbol": 64,
        "max_search_steps": 1,
    }
    plan = DiscoveryPlan.model_validate(raw_plan)
    states = enumerate_declaration_states(plan)
    products = (
        _product(
            adapter,
            states[0],
            tmp_path / "first.obj",
            _coff([(TARGET, bytes.fromhex("b802000000bb01000000c3"))]),
        ),
        _product(
            adapter,
            states[1],
            tmp_path / "second.obj",
            _coff([(TARGET, bytes.fromhex("b801000000bb02000000c3"))]),
        ),
    )

    with pytest.raises(DiscoveryError, match="exceeded max_search_steps 1"):
        adapter.analyze(
            campaign_id="campaign.neutral",
            plan=plan,
            products=products,
        )


def test_adapter_cache_material_is_stable_and_json_safe() -> None:
    reference = _coff([(TARGET, bytes.fromhex("33c0c3"))])
    adapter = MsvcDiscoveryAdapter(
        source=b"int neutral;\n",
        compiler=_NeverCompiler(),
        references=(MsvcFunctionReference.from_object(reference, TARGET),),
    )
    state = enumerate_declaration_states(_plan(1))[0]

    first: Mapping[str, JsonValue] = adapter.cache_material(state)
    second = adapter.cache_material(state)

    assert first == second
    changed_reference = _coff([(TARGET, bytes.fromhex("b801000000c3"))])
    changed = MsvcDiscoveryAdapter(
        source=b"int neutral;\n",
        compiler=_NeverCompiler(),
        references=(MsvcFunctionReference.from_object(changed_reference, TARGET),),
    )
    compile_authority = adapter.compile_authority_digest()
    changed_compile_authority = changed.compile_authority_digest()
    assert compile_authority == changed_compile_authority
    assert adapter.analysis_authority_digest(compile_authority) != (
        changed.analysis_authority_digest(changed_compile_authority)
    )
    assert "msvc_compile.py" in msvc_discovery._COMPILE_IMPLEMENTATION_PATHS
    assert "discovery.py" in msvc_discovery._COMPILE_IMPLEMENTATION_PATHS
    assert "discovery_contracts.py" in msvc_discovery._COMPILE_IMPLEMENTATION_PATHS
    assert "discovery.py" in msvc_discovery_analysis._ANALYSIS_IMPLEMENTATION_PATHS
    assert (
        "discovery_contracts.py"
        in msvc_discovery_analysis._ANALYSIS_IMPLEMENTATION_PATHS
    )
    assert "cache.py" in msvc_discovery._COMPILE_IMPLEMENTATION_PATHS
    assert "secure_paths.py" in msvc_discovery._COMPILE_IMPLEMENTATION_PATHS
    assert "msvc_discovery.py" in msvc_discovery._COMPILE_IMPLEMENTATION_PATHS
    assert (
        "msvc_discovery_analysis.py"
        not in msvc_discovery._COMPILE_IMPLEMENTATION_PATHS
    )
    assert (
        "msvc_discovery.py" in msvc_discovery_analysis._ANALYSIS_IMPLEMENTATION_PATHS
    )
    assert (
        "msvc_discovery_analysis.py"
        in msvc_discovery_analysis._ANALYSIS_IMPLEMENTATION_PATHS
    )
    assert not any(
        path.startswith("classic")
        for path in (
            *msvc_discovery._COMPILE_IMPLEMENTATION_PATHS,
            *msvc_discovery_analysis._ANALYSIS_IMPLEMENTATION_PATHS,
        )
    )


def test_request_is_strict_canonical_and_binds_planned_references() -> None:
    plan = _plan(1)
    request = MsvcDiscoveryRequest(
        source="src/widget.cpp",
        plan=plan,
        references=(MsvcDiscoveryObjectInput(symbol=TARGET, object="ref/widget.obj"),),
        compiler_arguments=("/nologo", "/O2", "/Gy", "/Z7"),
    )
    assert request.plan == plan

    with pytest.raises(ValidationError, match="canonical POSIX"):
        MsvcDiscoveryRequest.model_validate(
            {
                **request.model_dump(mode="python"),
                "source": "../widget.cpp",
            }
        )


def test_request_schema_matches_adversarial_model_boundaries() -> None:
    schema = msvc_discovery_request_json_schema()
    definitions = schema["$defs"]
    assert isinstance(definitions, dict)
    for name in (
        "DeclarationShapeSearch",
        "PadShapeSearch",
        "ForwardDeclarationSearch",
        "ExternRunPairSearch",
    ):
        model = definitions[name]
        assert isinstance(model, dict)
        assert "family" in model["required"]
    assert definitions["Range1To10"]["properties"]["stop"]["maximum"] == 10
    assert definitions["Range1To99"]["properties"]["stop"]["maximum"] == 99
    assert definitions["Range1To100"]["properties"]["stop"]["maximum"] == 100
    assert (
        definitions["DiscoveryPlan"]["properties"]["max_observed_functions"][
            "maximum"
        ]
        == 100_000
    )
    source_schema = schema["properties"]["source"]
    assert isinstance(source_schema, dict)
    path_pattern = re.compile(source_schema["pattern"])
    assert path_pattern.fullmatch("src/widget.cpp")
    assert not path_pattern.fullmatch("../widget.cpp")
    assert not path_pattern.fullmatch("src//widget.cpp")
    arguments = schema["properties"]["compiler_arguments"]["items"]["enum"]
    assert "/O2" in arguments
    assert "/Fa../../outside.asm" not in arguments

    request = MsvcDiscoveryRequest(
        source="widget.cpp",
        plan=_plan(1),
        references=(MsvcDiscoveryObjectInput(symbol=TARGET, object="reference.obj"),),
        compiler_arguments=("/nologo", "/O2", "/Ob1", "/Gy", "/Z7"),
    ).model_dump(mode="python")
    del request["plan"]["searches"][0]["family"]
    with pytest.raises(ValidationError, match="Unable to extract tag"):
        MsvcDiscoveryRequest.model_validate(request)
    request["plan"]["searches"][0]["family"] = "forward_declaration_run"
    request["source"] = "../widget.cpp"
    with pytest.raises(ValidationError, match="canonical POSIX"):
        MsvcDiscoveryRequest.model_validate(request)
    request["source"] = "widget.cpp"
    request["compiler_arguments"] = ("/Fa../../outside.asm",)
    with pytest.raises(ValidationError, match="path-free code-generation"):
        MsvcDiscoveryRequest.model_validate(request)


def test_committed_request_example_is_neutral_and_valid() -> None:
    example = (
        Path(__file__).parents[1]
        / "examples"
        / "declaration-discovery"
        / "campaign.json"
    )
    request = MsvcDiscoveryRequest.model_validate_json(example.read_bytes())

    assert request.plan.target == "sample"
    assert request.plan.max_cells == 4
    assert request.references[0].object == "reference.obj"


def test_analysis_parses_each_product_once_for_multiple_symbols(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_body = bytes.fromhex("b801000000c3")
    helper_body = bytes.fromhex("33c0c3")
    adapter = MsvcDiscoveryAdapter(
        source=b"int neutral;\n",
        compiler=_NeverCompiler(),
        references=(
            MsvcFunctionReference(TARGET, target_body),
            MsvcFunctionReference(HELPER, helper_body),
        ),
    )
    symbols = tuple(sorted((TARGET, HELPER), key=str.casefold))
    base = _plan(1)
    plan = DiscoveryPlan.model_validate(
        {**base.model_dump(mode="python"), "symbols": symbols}
    )
    state = enumerate_declaration_states(plan)[0]
    product = _product(
        adapter,
        state,
        tmp_path / "candidate.obj",
        _coff([(TARGET, target_body), (HELPER, helper_body)]),
    )
    product_parses = 0
    parse_coff = msvc_discovery_analysis._parse_coff

    def counted_parse(payload: bytes, context: str) -> CoffObject:
        nonlocal product_parses
        if context.startswith("discovery cell "):
            product_parses += 1
        return parse_coff(payload, context)

    monkeypatch.setattr(msvc_discovery_analysis, "_parse_coff", counted_parse)
    proposals = adapter.analyze(
        campaign_id="campaign.neutral",
        plan=plan,
        products=(product,),
    )

    assert product_parses == 1
    assert {
        item.symbol
        for item in proposals
        if item.kind is DiscoveryFindingKind.WHOLE_BODY
    } == set(symbols)


def test_observation_rejects_objects_above_the_function_index_limit(
    tmp_path: Path,
) -> None:
    adapter = MsvcDiscoveryAdapter(
        source=b"int neutral;\n",
        compiler=_NeverCompiler(),
        references=(MsvcFunctionReference(TARGET, b"\xc3"),),
    )
    state = enumerate_declaration_states(_plan(1))[0]
    functions = [(f"?Function{index:04d}@@YAHXZ", b"\xc3") for index in range(4097)]

    with pytest.raises(DiscoveryError, match="per-object limit is 4096"):
        _product(adapter, state, tmp_path / "oversized.obj", _coff(functions))


def test_direct_compiler_revalidates_authority_and_rejects_hidden_inputs(
    tmp_path: Path,
) -> None:
    wrapper = Path(sys.executable).resolve(strict=True)
    support = tmp_path / "wine"
    support.write_bytes(b"runtime")
    expected = Digest.from_bytes(b"locked toolchain")
    received = expected
    probe_count = 0

    def probe() -> Digest:
        nonlocal probe_count
        probe_count += 1
        return received

    compiler = DirectMsvcCompiler.create(
        wrapper=wrapper,
        arguments=("/nologo", "/O2", "/Ob1", "/Gy", "/Z7"),
        environment={},
        toolchain_authority=expected,
        support_files=(support,),
        toolchain_authority_probe=probe,
    )
    compiler.authority_digest()
    assert probe_count == 1

    support.write_bytes(b"changed runtime")
    with pytest.raises(DiscoveryError, match="compiler context changed"):
        compiler.authority_digest()
    assert probe_count == 2

    support.write_bytes(b"runtime")
    received = Digest.from_bytes(b"changed lock")
    with pytest.raises(DiscoveryError, match="authority changed"):
        compiler.authority_digest()
    assert probe_count == 3

    with pytest.raises(DiscoveryError, match="path-free code-generation"):
        DirectMsvcCompiler.create(
            wrapper=wrapper,
            arguments=("/nologo", "/I../unsealed"),
            environment={"PATH": "/usr/bin"},
            toolchain_authority=expected,
        )


@pytest.mark.skipif(os.name != "posix", reason="uses a tiny POSIX compiler stand-in")
def test_direct_compiler_cancellation_terminates_active_process_tree(
    tmp_path: Path,
) -> None:
    wrapper = tmp_path / "compiler"
    wrapper.write_text(
        "#!/bin/sh\n: > started.marker\nsleep 30\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    compiler = DirectMsvcCompiler.create(
        wrapper=wrapper,
        arguments=("/nologo",),
        environment={"PATH": os.environ["PATH"]},
        toolchain_authority=Digest.from_bytes(b"test toolchain"),
        timeout_seconds=30,
    )
    cancellation = CancellationToken()
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            compiler.compile,
            RenderedMsvcState(b"int neutral;\n", None, b"", ()),
            workspace,
            cancellation,
        )
        marker = workspace / "started.marker"
        deadline = time.monotonic() + 2
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert marker.exists()
        cancellation.cancel("test interruption")
        with pytest.raises(ProcessCancelled, match="test interruption"):
            future.result(timeout=3)

    assert time.monotonic() - started < 3


@pytest.mark.parametrize(
    "argument",
    (
        "@arguments.rsp",
        "unit.cpp",
        "/DNAME=1",
        "/Fa../../outside.asm",
        "/FA",
        "/Fd../../outside.pdb",
        "/Fe../../outside.exe",
        "/FI../../outside.h",
        "/Fm../../outside.map",
        "/Fo../../outside.obj",
        "/Fp../../outside.pch",
        "/FR../../outside.sbr",
        "/I../../outside",
        "/Tcunit.cpp",
        "/Tpunit.cpp",
        "/Ycprecompiled.h",
    ),
)
def test_direct_compiler_rejects_every_unadmitted_or_path_writing_switch(
    argument: str,
) -> None:
    with pytest.raises(DiscoveryError, match="path-free code-generation"):
        DirectMsvcCompiler.create(
            wrapper=Path(sys.executable).resolve(strict=True),
            arguments=(argument,),
            environment={},
            toolchain_authority=Digest.from_bytes(b"locked toolchain"),
        )
