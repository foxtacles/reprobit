from __future__ import annotations

import struct
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from reprobit.classic.coff_evidence import (
    _CoffObject,
    _parse_coff,
    parse_classic_archive_member_directives,
    parse_classic_coff_directives,
    parse_classic_import_object,
)
from reprobit.classic.coff_projection import (
    _coff_compiler_congruence_trace,
    _CrtPullLinkerDependency,
    _linkage_statement,
    _OrderedArchiveSeedDependency,
    _runtime_projection,
    _runtime_projection_equivalence,
    _runtime_projection_equivalence_proof,
    _semantic_code_stream,
    _SemanticCodePartitionError,
    classic_link_relevant_coff_projection,
    prove_classic_coff_line_number_correspondence,
)
from reprobit.classic.compiler_epoch import (
    _crt_pull_linker_dependencies,
    _helper_delta_sections,
    _macro_capture_collisions,
    _portable_tree_statement,
    _seed_order_dependencies,
    _validate_compiler_invocation,
    _validate_compiler_namespaces,
    classic_compiler_path_profile_digest,
    compiler_epoch_invocation_digest,
    compiler_namespace_evidence_digest,
    validate_project_overlay_compiler_epoch,
)
from reprobit.classic.linker_identity import issue_msvc420_linker_identity
from reprobit.classic.overlay_declarations import (
    _DeclarationFact,
    _validate_declaration_odr,
)
from reprobit.classic.project_overlay import (
    _archive_semantics,
    _carrier_isolation_trace,
    _helper_isolation_trace,
    _msvc_function_auxiliary_receipt,
    _overlay_lane_input_is_authorized,
    _OverlayOutputOwner,
    overlay_semantic_run_binding,
    prove_source_overlay_semantics,
)
from reprobit.classic.semantic_contracts import (
    _CLASSIC_SEMANTIC_ISSUER,
    CLASSIC_SEMANTIC_CONTRACTS,
    SOURCE_OVERLAY_OBLIGATIONS,
    SOURCE_OVERLAY_VALIDATOR_DIGEST,
    SOURCE_OVERLAY_VALIDATOR_ID,
    ArchiveInput,
    CleanSourceInput,
    CompilerEpochInvocation,
    CompilerNamespaceEvidence,
    CompilerProduct,
    CompilerSourceRead,
    DonorSemanticLane,
    DonorSemanticUse,
    EffectiveOverlayReceipt,
    OverlaySemanticSnapshot,
    PrimarySourceOrigin,
    ProjectOverlayCompilerEpochPlan,
    ProjectOverlayCounterfactualAudit,
    ProjectOverlaySourcePair,
    SourceInputReceipt,
    TargetLinkClosure,
    _ClassicCandidateSemanticMaterial,
    _ClassicDonorSemanticMaterial,
    _issue_semantic_proof,
    classic_candidate_input_statement,
    issue_classic_candidate_semantics,
    issue_classic_donor_semantics,
    semantic_proof_matches,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.classic.source_overlay import plan_project_overlay_compiler_epochs
from reprobit.classic.source_overlay_claims import (
    _assert_reseat_removed_tokens,
    _compiler_has_define,
    _compiler_has_undefine,
    _has_unconditional_standard_assert_include,
    _payload_preprocessor_mutations,
    _require_no_compiler_macro_capture,
    _standard_assert_header_is_unshadowed,
    _validate_unreachable_helper_leaf,
)
from reprobit.classic.source_proofs import source_overlay_tokens
from reprobit.classic_includes import IncludeOrigin
from reprobit.classic_overlay import (
    ClassicOverlayAnchorReceipt,
    ClassicOverlayOperationReceipt,
)
from reprobit.classic_project import ClassicProjectError
from reprobit.classic_resources import (
    ResourceDependencyReceipt,
    ResourceRead,
    ResourceReadKind,
)
from reprobit.classic_runtime_producer import _project_overlay_resource_reader_closure
from reprobit.model import Digest, Scope
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerNode,
    ProducerRole,
    source_topology_digest,
    toolchain_document_digest,
)
from reprobit.schema import (
    BuildPlanDocument,
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    ClassicTargetGate,
    ClassicTranslationUnitPlan,
    InputTreeReceipt,
    InterventionDocument,
    LockedTool,
    LogicalPathProfile,
    MsvcRelease,
    OracleDocument,
    ProducerGraphBuildAdapter,
    ProjectBundle,
    ProjectSpec,
    ProofDocument,
    SourceManifestDocument,
    SourceManifestEntry,
    TargetSpec,
    ToolchainLock,
    ToolchainProfileSource,
    ToolchainRef,
    source_manifest_digest,
)
from reprobit.strict_json import canonical_json


def test_preprocessor_census_streams_tokens_and_reuses_prevalidated_payloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"/* ignored */ # define Captured 1\n#undef Released\n"
    digest = Digest.from_bytes(payload)
    calls = 0

    def tokens(_payload: bytes) -> Iterator[tuple[str, int, int]]:
        nonlocal calls
        calls += 1
        assert _payload is payload
        yield "#", 14, 15
        yield "define", 16, 22
        yield "Captured", 23, 31
        yield "1", 32, 33
        yield "#", 34, 35
        yield "undef", 35, 40
        yield "Released", 41, 49

    monkeypatch.setattr("reprobit.classic.source_overlay_claims.iter_source_overlay_tokens", tokens)
    cache: dict[tuple[Digest, int], frozenset[tuple[str, str]]] = {}

    first = _payload_preprocessor_mutations((payload,), prevalidated_digests=(digest,), cache=cache)
    second = _payload_preprocessor_mutations(
        (payload,), prevalidated_digests=(digest,), cache=cache
    )

    assert first == second == frozenset({("define", "Captured"), ("undef", "Released")})
    assert calls == 1


def test_preprocessor_census_rejects_misaligned_prevalidated_digests() -> None:
    payload = b"#define Captured 1\n"
    digest = Digest.from_bytes(payload)

    with pytest.raises(ClassicSemanticError, match="fewer prevalidated digests"):
        _payload_preprocessor_mutations((payload,), prevalidated_digests=(), cache={})
    with pytest.raises(ClassicSemanticError, match="more prevalidated digests"):
        _payload_preprocessor_mutations((), prevalidated_digests=(digest,), cache={})


@pytest.mark.parametrize(
    "payload",
    (
        b"%:define Captured 1\n",
        b"??=define Captured 1\n",
        b"#de\\\nfine Captured 1\n",
    ),
)
def test_preprocessor_census_applies_directive_translation_phases(payload: bytes) -> None:
    assert _payload_preprocessor_mutations((payload,)) == frozenset({("define", "Captured")})


@pytest.mark.parametrize(
    "payload",
    (
        b"plain binary define text without a hash\0\xff",
        b"hash only # and no directive token",
        b"#defined NotADirective\n",
        b"/* #define Commented 1 */\n",
        b'const char *text = "#undef Quoted";\n',
        b"\0#define BinaryAdjacent 1\n",
        b"# /* gap */ define Real 1\n",
        b"#undef Released\n",
        "#define\N{LATIN SMALL LETTER E WITH ACUTE} NotStandalone\n".encode("latin1"),
    ),
)
def test_preprocessor_candidate_filter_matches_the_original_token_theorem(
    payload: bytes,
) -> None:
    tokens = tuple(token for token, _start, _end in source_overlay_tokens(payload))
    expected: set[tuple[str, str]] = set()
    for index in range(len(tokens) - 2):
        if tokens[index] == "#" and tokens[index + 1] in {"define", "undef"}:
            identifier = tokens[index + 2]
            if (
                identifier.isascii()
                and (identifier[:1].isalpha() or identifier.startswith("_"))
                and all(character.isalnum() or character == "_" for character in identifier)
            ):
                expected.add((tokens[index + 1], identifier))

    assert _payload_preprocessor_mutations((payload,)) == frozenset(expected)


def test_preprocessor_candidate_filter_skips_noncandidate_binary_lexing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "reprobit.classic.source_overlay_claims.iter_source_overlay_tokens",
        lambda _payload: pytest.fail("noncandidate payload was tokenized"),
    )

    assert _payload_preprocessor_mutations((b"define in a large binary" * 1000,)) == frozenset()


def test_macro_capture_census_admits_only_the_owning_record_header_guard() -> None:
    intrinsic = frozenset({("src/generated.h", "define", "FRESH_GUARD")})
    sensitive = frozenset({"FRESH_GUARD", "FreshRecord"})

    assert (
        _macro_capture_collisions(
            (("source/src/GENERATED.h", "define", "FRESH_GUARD"),),
            sensitive_identifiers=sensitive,
            intrinsic_source_mutations=intrinsic,
        )
        == ()
    )

    hostile = (
        ("toolchain/include/runtime.h", "define", "FRESH_GUARD"),
        ("source/src/other.h", "define", "FRESH_GUARD"),
        ("source/src/generated.h", "undef", "FRESH_GUARD"),
        ("source/src/generated.h", "define", "FreshRecord"),
    )
    assert _macro_capture_collisions(
        hostile,
        sensitive_identifiers=sensitive,
        intrinsic_source_mutations=intrinsic,
    ) == ("FRESH_GUARD", "FreshRecord")


def test_macro_capture_checks_generated_compiler_command_lines() -> None:
    ordinary = ProducerNode(
        id="compiler.app.ordinary",
        role=ProducerRole.COMPILER,
        owner="app",
        arguments=("/c", "${SOURCE}/src/unit.cpp"),
        inputs=("source/src/unit.cpp",),
        outputs=("build/obj/unit.obj",),
    )
    generated = ProducerNode(
        id="compiler.app.carrier",
        role=ProducerRole.COMPILER,
        owner="app",
        arguments=("/DFRESH_GUARD=Captured", "/c", "${SOURCE}/src/carrier.cpp"),
        inputs=("source/src/carrier.cpp",),
        outputs=("build/obj/carrier.obj",),
    )

    with pytest.raises(ClassicSemanticError, match=r"compiler\.app\.carrier.*macro-capture"):
        _require_no_compiler_macro_capture(
            (ordinary, generated),
            frozenset({"FRESH_GUARD"}),
        )


@pytest.mark.parametrize(
    ("define_arguments", "label"),
    (
        (("/DCaptured#1",), "hash-attached"),
        (("/D", "Captured#1"), "hash-separated"),
        (("-DCaptured#1",), "dash-hash-attached"),
        (("-D", "Captured#1"), "dash-hash-separated"),
        (("/DCaptured(value)=value",), "function-attached"),
        (("/D", "Captured(value)=value"), "function-separated"),
    ),
)
def test_compiler_define_recognizes_value_and_function_separators(
    define_arguments: tuple[str, ...],
    label: str,
) -> None:
    node = ProducerNode(
        id=f"compiler.app.{label}",
        role=ProducerRole.COMPILER,
        owner="app",
        arguments=(*define_arguments, "/c", "${SOURCE}/src/unit.cpp"),
        inputs=("source/src/unit.cpp",),
        outputs=("build/obj/unit.obj",),
    )

    assert _compiler_has_define(node, "Captured")


@pytest.mark.parametrize("arguments", (("/UNDEBUG",), ("/U", "NDEBUG"), ("-UNDEBUG",)))
def test_compiler_undefine_recognizes_attached_and_separated_forms(
    arguments: tuple[str, ...],
) -> None:
    node = ProducerNode(
        id="compiler.app.undefine",
        role=ProducerRole.COMPILER,
        owner="app",
        arguments=(*arguments, "/c", "${SOURCE}/src/unit.cpp"),
        inputs=("source/src/unit.cpp",),
        outputs=("build/obj/unit.obj",),
    )

    assert _compiler_has_undefine(node, "NDEBUG")


@pytest.mark.parametrize(
    ("prefix", "expected"),
    (
        (b"#include <assert.h>\n", True),
        (b"#if 0\n#include <assert.h>\n#endif\n", False),
        (b'#include "assert.h"\n', False),
        (b"/*\n#include <assert.h>\n*/\n", False),
        (b"#if 0\n#endif\n#include <assert.h> // standard binding\n", True),
    ),
)
def test_assert_reseat_requires_an_unconditional_standard_header_before_its_function(
    prefix: bytes,
    expected: bool,
) -> None:
    payload = prefix + b"void Bound() {}\n#include <assert.h>\n"

    assert (
        _has_unconditional_standard_assert_include(
            payload,
            before_offset=payload.index(b"void Bound"),
        )
        is expected
    )


def test_assert_reseat_rejects_a_project_header_that_shadows_the_toolchain() -> None:
    node = ProducerNode(
        id="compiler.app.unit",
        role=ProducerRole.COMPILER,
        owner="app",
        arguments=("/I", "${SOURCE}/include", "/c", "${SOURCE}/src/unit.cpp"),
        inputs=("source/src/unit.cpp",),
        outputs=("build/obj/unit.obj",),
    )

    assert _standard_assert_header_is_unshadowed((node,), {})
    assert not _standard_assert_header_is_unshadowed(
        (node,),
        {"include/assert.h": "include/assert.h"},
    )
    root_node = node.model_copy(
        update={"arguments": ("/I${SOURCE}", "/c", "${SOURCE}/src/unit.cpp")}
    )
    assert not _standard_assert_header_is_unshadowed(
        (root_node,),
        {"assert.h": "assert.h"},
    )


def _assert_delete_receipt(*, start: int, end: int) -> ClassicOverlayOperationReceipt:
    return ClassicOverlayOperationReceipt(
        operation_id="op_assert_delete",
        action="delete",
        fragment_digest="0" * 64,
        fragment_size=0,
        anchors=(
            ClassicOverlayAnchorReceipt("start", "0" * 64, 0, start),
            ClassicOverlayAnchorReceipt("end", "0" * 64, 0, end),
        ),
    )


def test_assert_reseat_binds_the_exact_removed_assertion_tokens() -> None:
    statement = b"assert(v1 && v2);"
    payload = b"void Bound() {\n\t" + statement + b"\n}\n"
    start = payload.index(statement)

    identifiers = _assert_reseat_removed_tokens(
        leaf={
            "condition": "v1_and_v2",
            "restore_seat": {
                "kind": "after_local_declaration_sequence",
                "declarations": [{"identifier": "v1"}, {"identifier": "v2"}],
            },
        },
        operation_receipt=_assert_delete_receipt(start=start, end=start + len(statement)),
        clean_payload=payload,
        function_range=(0, len(payload)),
    )

    assert identifiers == ("v1", "v2")


def test_assert_reseat_rejects_an_arbitrary_removed_statement() -> None:
    statement = b"consume(v1 && v2);"
    payload = b"void Bound() {\n\t" + statement + b"\n}\n"
    start = payload.index(statement)

    with pytest.raises(ClassicSemanticError, match="not its declared assertion"):
        _assert_reseat_removed_tokens(
            leaf={
                "condition": "v1_and_v2",
                "restore_seat": {
                    "kind": "after_local_declaration_sequence",
                    "declarations": [{"identifier": "v1"}, {"identifier": "v2"}],
                },
            },
            operation_receipt=_assert_delete_receipt(start=start, end=start + len(statement)),
            clean_payload=payload,
            function_range=(0, len(payload)),
        )


@dataclass(frozen=True, slots=True)
class _Contract:
    validator_id: str
    validator_digest: Digest
    obligations: tuple[str, ...]


_BINARY_CONTRACT = _Contract(
    "classic.equal-body-strict.v1",
    Digest.from_bytes(b"reviewed equal-body validator v1"),
    ("binary.equal_body",),
)


def _declaration_fact(
    *,
    identifier: str = "FreshRecord",
    primary: str | None = None,
    disposition: str = "record-definition",
    signature: bytes = b"class FreshRecord {};",
    source: str,
    targets: tuple[str, ...] = ("program",),
    tag: str | None = "class",
) -> _DeclarationFact:
    return _DeclarationFact(
        identifier,
        primary or identifier,
        disposition,
        tag,
        Digest.from_bytes(signature),
        source,
        frozenset(targets),
    )


def _bound_snapshot(
    graph: ProducerGraphDocument, snapshot: OverlaySemanticSnapshot
) -> OverlaySemanticSnapshot:
    return replace(snapshot, run_binding=overlay_semantic_run_binding(graph, snapshot))


def _compiler_invocation(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    node: ProducerNode,
    reads: tuple[CompilerSourceRead, ...],
    *,
    namespace_id: str,
) -> tuple[CompilerEpochInvocation, CompilerNamespaceEvidence]:
    tool = next(item for item in bundle.toolchain_lock.tools if "compiler" in item.roles)
    fixture_tool_payload = b"cl"
    assert tool.digest == Digest.from_bytes(fixture_tool_payload)
    assert tool.size == len(fixture_tool_payload)
    complete_reads = tuple(
        sorted(
            (
                *reads,
                CompilerSourceRead(
                    f"toolchain/{tool.path}",
                    tool.digest,
                    len(fixture_tool_payload),
                    None,
                    fixture_tool_payload,
                ),
            ),
            key=lambda item: item.reference.casefold(),
        )
    )
    namespace = CompilerNamespaceEvidence(
        namespace_id,
        Digest.from_bytes(b"placeholder namespace"),
        complete_reads,
    )
    namespace = replace(
        namespace,
        namespace_digest=compiler_namespace_evidence_digest(namespace),
    )
    value = CompilerEpochInvocation(
        tool.id,
        tool.digest,
        node.arguments,
        bundle.spec.paths.build,
        Digest.from_bytes(b"sealed compiler-visible environment"),
        classic_compiler_path_profile_digest(bundle, graph),
        Digest.from_bytes(b"placeholder invocation"),
        namespace.namespace_id,
        namespace.namespace_digest,
        len(namespace.members),
    )
    return (
        replace(value, invocation_digest=compiler_epoch_invocation_digest(value)),
        namespace,
    )


def _symbol(
    name: str,
    *,
    value: int = 0,
    section: int,
    symbol_type: int,
    storage: int,
    auxiliary_count: int = 0,
) -> bytes:
    encoded = name.encode("ascii")
    assert len(encoded) <= 8
    return encoded.ljust(8, b"\0") + struct.pack(
        "<IhHBB", value, section, symbol_type, storage, auxiliary_count
    )


def _coff_object(
    definition: str,
    *,
    definition_type: int = 32,
    reference: str | None = None,
    reference_type: int = 0,
    section_name: str = ".text",
    body_payload: bytes | None = None,
    relocation_offset_in_section: int = 0,
    relocation_type: int = 6,
    relocate_reference: bool = True,
) -> bytes:
    """Build the tiny strict COMDAT subset used by ancestry fixtures."""

    body = (
        body_payload
        if body_payload is not None
        else b"\0\0\0\0"
        if reference is not None
        else b"\xc3"
    )
    section_table_end = 20 + 40
    has_relocation = reference is not None and relocate_reference
    relocation_offset = section_table_end + len(body) if has_relocation else 0
    relocation = b""
    symbols = [
        _symbol(
            section_name,
            section=1,
            symbol_type=0,
            storage=3,
            auxiliary_count=1,
        ),
        # Section-definition auxiliary: selection=2 (pick any).
        struct.pack("<IHHIhBBH", len(body), int(has_relocation), 0, 0, 0, 2, 0, 0),
        _symbol(definition, section=1, symbol_type=definition_type, storage=2),
    ]
    if reference is not None:
        target_index = 3
        symbols.append(_symbol(reference, section=0, symbol_type=reference_type, storage=2))
        if has_relocation:
            relocation = struct.pack(
                "<IIH", relocation_offset_in_section, target_index, relocation_type
            )
    symbol_table = b"".join(symbols)
    symbol_offset = section_table_end + len(body) + len(relocation)
    header = struct.pack("<HHIIIHH", 0x14C, 1, 0xAABBCCDD, symbol_offset, len(symbols), 0, 0)
    section = section_name.encode("ascii").ljust(8, b"\0") + struct.pack(
        "<IIIIIIHHI",
        0,
        0,
        len(body),
        section_table_end,
        relocation_offset,
        0,
        int(has_relocation),
        0,
        0x60501020,
    )
    return header + section + body + relocation + symbol_table + struct.pack("<I", 4)


def _coff_function_provider_with_auxiliary(
    definition: str,
    *,
    next_definition: str | None = None,
    line_pointer_delta: int = 0,
    line_zero_target_index: int | None = None,
    next_function_index: int | None = None,
    begin_next_tag_index: int | None = None,
) -> bytes:
    """Build the canonical MSVC function/.bf/line-table chain used by LINK 4.20."""

    body = b"\x90\xc3"
    section_table_end = 20 + 40
    line_offset = section_table_end + len(body)
    first_function_index = 2
    first_tag_index = 4
    second_function_index = 6 if next_definition is not None else 0
    second_tag_index = 8 if next_definition is not None else 0
    effective_next_function_index = (
        second_function_index if next_function_index is None else next_function_index
    )
    effective_begin_next_tag_index = (
        second_tag_index if begin_next_tag_index is None else begin_next_tag_index
    )

    def function_auxiliary(tag_index: int, next_index: int) -> bytes:
        return struct.pack(
            "<IIIIH",
            tag_index,
            len(body),
            line_offset + line_pointer_delta,
            next_index,
            0,
        )

    def begin_auxiliary(source_line: int, next_tag: int) -> bytes:
        return (
            bytes(4)
            + struct.pack("<H", source_line)
            + bytes(6)
            + struct.pack("<I", next_tag)
            + bytes(2)
        )

    symbols = [
        _symbol(".text", section=1, symbol_type=0, storage=3, auxiliary_count=1),
        struct.pack("<IHHIhBBH", len(body), 0, 1, 0, 0, 2, 0, 0),
        _symbol(
            definition,
            section=1,
            symbol_type=0x20,
            storage=2,
            auxiliary_count=1,
        ),
        function_auxiliary(first_tag_index, effective_next_function_index),
        _symbol(".bf", section=1, symbol_type=0, storage=101, auxiliary_count=1),
        begin_auxiliary(11, effective_begin_next_tag_index),
    ]
    if next_definition is not None:
        symbols.extend(
            (
                _symbol(
                    next_definition,
                    section=1,
                    symbol_type=0x20,
                    storage=2,
                    auxiliary_count=1,
                ),
                function_auxiliary(second_tag_index, 0),
                _symbol(".bf", section=1, symbol_type=0, storage=101, auxiliary_count=1),
                begin_auxiliary(23, 0),
            )
        )
    symbol_table = b"".join(symbols)
    line_target = first_function_index if line_zero_target_index is None else line_zero_target_index
    line_table = struct.pack("<IH", line_target, 0)
    symbol_offset = line_offset + len(line_table)
    header = struct.pack(
        "<HHIIIHH",
        0x14C,
        1,
        0xAABBCCDD,
        symbol_offset,
        len(symbols),
        0,
        0,
    )
    section = b".text\0\0\0" + struct.pack(
        "<IIIIIIHHI",
        0,
        0,
        len(body),
        section_table_end,
        0,
        line_offset,
        0,
        1,
        0x60501020,
    )
    return header + section + body + line_table + symbol_table + struct.pack("<I", 4)


def _coff_const_pool(
    *,
    relocation: bool = False,
    external_owner: bool = False,
) -> bytes:
    body = bytes(range(20))
    section_table_end = 20 + 40
    relocation_offset = section_table_end + len(body) if relocation else 0
    symbols = (
        _symbol(".rdata", section=1, symbol_type=0, storage=3, auxiliary_count=1),
        struct.pack(
            "<IHHIhBBH",
            len(body),
            1 if relocation else 0,
            0,
            0,
            0,
            0,
            0,
            0,
        ),
        _symbol("_pool", section=1, symbol_type=0, storage=2 if external_owner else 3),
    )
    relocation_bytes = struct.pack("<IIH", 0, 2, 6) if relocation else b""
    symbol_table = b"".join(symbols)
    symbol_offset = section_table_end + len(body) + len(relocation_bytes)
    header = struct.pack("<HHIIIHH", 0x14C, 1, 0xAABBCCDD, symbol_offset, len(symbols), 0, 0)
    section = b".rdata\0\0" + struct.pack(
        "<IIIIIIHHI",
        0,
        0,
        len(body),
        section_table_end,
        relocation_offset,
        0,
        1 if relocation else 0,
        0,
        0x40400040,
    )
    return header + section + body + relocation_bytes + symbol_table + struct.pack("<I", 4)


def _coff_object_with_associative_chain(
    definition: str,
    *,
    cycle: bool = False,
    orphan: bool = False,
) -> bytes:
    bodies = (b"\xc3", bytes(16), b"debug")
    section_table_end = 20 + 3 * 40
    body_offsets = (
        section_table_end,
        section_table_end + len(bodies[0]),
        section_table_end + len(bodies[0]) + len(bodies[1]),
    )
    second_parent = 4 if orphan else 3 if cycle else 1
    third_parent = 2
    symbols = (
        _symbol(".text", section=1, symbol_type=0, storage=3, auxiliary_count=1),
        struct.pack("<IHHIhBBH", len(bodies[0]), 0, 0, 0, 0, 2, 0, 0),
        _symbol(definition, section=1, symbol_type=32, storage=2),
        _symbol(".debug$F", section=2, symbol_type=0, storage=3, auxiliary_count=1),
        struct.pack("<IHHIhBBH", len(bodies[1]), 0, 0, 0, second_parent, 5, 0, 0),
        _symbol(".debug$S", section=3, symbol_type=0, storage=3, auxiliary_count=1),
        struct.pack("<IHHIhBBH", len(bodies[2]), 0, 0, 0, third_parent, 5, 0, 0),
    )
    symbol_table = b"".join(symbols)
    symbol_offset = body_offsets[2] + len(bodies[2])
    header = struct.pack("<HHIIIHH", 0x14C, 3, 0xAABBCCDD, symbol_offset, len(symbols), 0, 0)

    def section(name: bytes, size: int, offset: int, characteristics: int) -> bytes:
        return name.ljust(8, b"\0") + struct.pack(
            "<IIIIIIHHI", 0, 0, size, offset, 0, 0, 0, 0, characteristics
        )

    section_table = b"".join(
        (
            section(b".text", len(bodies[0]), body_offsets[0], 0x60501020),
            section(b".debug$F", len(bodies[1]), body_offsets[1], 0x42101048),
            section(b".debug$S", len(bodies[2]), body_offsets[2], 0x42101048),
        )
    )
    return header + section_table + b"".join(bodies) + symbol_table + struct.pack("<I", 4)


def _coff_object_with_unreachable_helper_dependency(
    *,
    retained_reference: bool = False,
    retained_helper_reference: bool = False,
    extra_undefined: str | None = None,
) -> bytes:
    """Build one retained function plus one dead helper that calls ``_pull``."""

    has_retained_relocation = retained_reference or retained_helper_reference
    retained_body = b"\0\0\0\0" if has_retained_relocation else b"\xc3"
    helper_body = b"\xe8\0\0\0\0\xc3"
    section_table_end = 20 + 2 * 40
    retained_offset = section_table_end
    helper_offset = retained_offset + len(retained_body)
    retained_relocation_offset = helper_offset + len(helper_body) if has_retained_relocation else 0
    helper_relocation_offset = (
        helper_offset + len(helper_body) + (10 if has_retained_relocation else 0)
    )
    symbols = [
        _symbol(".text", section=1, symbol_type=0, storage=3, auxiliary_count=1),
        struct.pack(
            "<IHHIhBBH",
            len(retained_body),
            1 if has_retained_relocation else 0,
            0,
            0,
            0,
            2,
            0,
            0,
        ),
        _symbol("_entry", section=1, symbol_type=32, storage=2),
        _symbol(".text", section=2, symbol_type=0, storage=3, auxiliary_count=1),
        struct.pack("<IHHIhBBH", len(helper_body), 1, 0, 0, 0, 2, 0, 0),
        _symbol("_helper", section=2, symbol_type=32, storage=2),
        _symbol("_pull", section=0, symbol_type=32, storage=2),
    ]
    if extra_undefined is not None:
        symbols.append(_symbol(extra_undefined, section=0, symbol_type=32, storage=2))
    symbol_table = b"".join(symbols)
    symbol_offset = helper_relocation_offset + 10
    header = struct.pack("<HHIIIHH", 0x14C, 2, 0xAABBCCDD, symbol_offset, len(symbols), 0, 0)
    retained_section = b".text\0\0\0" + struct.pack(
        "<IIIIIIHHI",
        0,
        0,
        len(retained_body),
        retained_offset,
        retained_relocation_offset,
        0,
        1 if has_retained_relocation else 0,
        0,
        0x60501020,
    )
    helper_section = b".text\0\0\0" + struct.pack(
        "<IIIIIIHHI",
        0,
        0,
        len(helper_body),
        helper_offset,
        helper_relocation_offset,
        0,
        1,
        0,
        0x60501020,
    )
    retained_relocation = (
        struct.pack("<IIH", 0, 5 if retained_helper_reference else 6, 0x14)
        if has_retained_relocation
        else b""
    )
    helper_relocation = struct.pack("<IIH", 1, 6, 0x14)
    return (
        header
        + retained_section
        + helper_section
        + retained_body
        + helper_body
        + retained_relocation
        + helper_relocation
        + symbol_table
        + struct.pack("<I", 4)
    )


def _coff_object_with_ordered_archive_seed(
    *,
    retained_payload: bytes | None = None,
    undefined_order: tuple[str, ...] | None = None,
    first_target: str = "_pull_a",
    second_target: str = "_pull_b",
    first_relocation_type: int = 0x14,
    first_addend: int = 0,
    retained_reference: str | None = None,
    extra_undefined: str | None = None,
    duplicate_first_row: bool = False,
    first_row_value: int = 0,
    first_row_type: int = 0x20,
    first_row_storage: int = 2,
    first_row_auxiliary_count: int = 0,
    data_target: str | None = None,
    data_relocation_type: int = 0x06,
    data_relocation_offset: int = 11,
    data_addend: int = 0,
    data_row_value: int = 0,
    data_row_type: int = 0,
    data_row_storage: int = 2,
    data_row_auxiliary_count: int = 0,
    drop_data_relocation: bool = False,
    retained_section_name: str = ".text",
) -> bytes:
    """Build retained code plus a private ``SeedOrder`` with typed bindings."""

    retained_body = (
        retained_payload
        if retained_payload is not None
        else b"\0\0\0\0"
        if retained_reference is not None
        else b"\xc3"
    )
    helper_body = (
        b"\xe8"
        + first_addend.to_bytes(4, "little", signed=True)
        + b"\xe8\0\0\0\0"
        + (
            b"\xa1" + data_addend.to_bytes(4, "little", signed=True)
            if data_target is not None
            else b""
        )
        + b"\xc3"
    )
    string_payload = bytearray()
    symbols: list[bytes] = []
    symbol_indexes: dict[str, int] = {}

    def add_symbol(
        name: str,
        *,
        value: int = 0,
        section: int,
        symbol_type: int,
        storage: int,
        auxiliary: bytes = b"",
    ) -> None:
        assert not auxiliary or len(auxiliary) % 18 == 0
        encoded = name.encode("ascii")
        if len(encoded) <= 8:
            raw_name = encoded.ljust(8, b"\0")
        else:
            string_offset = 4 + len(string_payload)
            raw_name = b"\0\0\0\0" + struct.pack("<I", string_offset)
            string_payload.extend(encoded + b"\0")
        symbol_indexes.setdefault(name, len(symbols))
        auxiliary_count = len(auxiliary) // 18
        symbols.append(
            raw_name
            + struct.pack(
                "<IhHBB",
                value,
                section,
                symbol_type,
                storage,
                auxiliary_count,
            )
        )
        symbols.extend(auxiliary[index : index + 18] for index in range(0, len(auxiliary), 18))

    add_symbol(
        retained_section_name,
        section=1,
        symbol_type=0,
        storage=3,
        auxiliary=struct.pack(
            "<IHHIhBBH",
            len(retained_body),
            1 if retained_reference is not None else 0,
            0,
            0,
            0,
            2,
            0,
            0,
        ),
    )
    add_symbol("_entry", section=1, symbol_type=0x20, storage=2)
    add_symbol(
        ".text",
        section=2,
        symbol_type=0,
        storage=3,
        auxiliary=struct.pack(
            "<IHHIhBBH",
            len(helper_body),
            2 + int(data_target is not None and not drop_data_relocation),
            0,
            0,
            0,
            2,
            0,
            0,
        ),
    )
    add_symbol("?SeedOrder@@YAXXZ", section=2, symbol_type=0x20, storage=2)
    effective_undefined_order = undefined_order or (
        ((data_target,) if data_target is not None else ()) + ("_pull_b", "_pull_a")
    )
    for name in effective_undefined_order:
        add_symbol(
            name,
            value=(
                data_row_value
                if name == data_target
                else first_row_value
                if name == "_pull_a"
                else 0
            ),
            section=0,
            symbol_type=(
                data_row_type
                if name == data_target
                else first_row_type
                if name == "_pull_a"
                else 0x20
            ),
            storage=(
                data_row_storage
                if name == data_target
                else first_row_storage
                if name == "_pull_a"
                else 2
            ),
            auxiliary=(
                bytes(18) * data_row_auxiliary_count
                if name == data_target
                else bytes(18) * first_row_auxiliary_count
                if name == "_pull_a"
                else b""
            ),
        )
    if duplicate_first_row:
        add_symbol("_pull_a", section=0, symbol_type=0x20, storage=2)
    if extra_undefined is not None:
        add_symbol(extra_undefined, section=0, symbol_type=0x20, storage=2)

    section_table_end = 20 + 2 * 40
    retained_offset = section_table_end
    helper_offset = retained_offset + len(retained_body)
    retained_relocation_offset = (
        helper_offset + len(helper_body) if retained_reference is not None else 0
    )
    helper_relocation_offset = (
        helper_offset + len(helper_body) + (10 if retained_reference is not None else 0)
    )
    retained_relocation = (
        struct.pack("<IIH", 0, symbol_indexes[retained_reference], 0x14)
        if retained_reference is not None
        else b""
    )
    helper_relocation_rows = [
        struct.pack("<IIH", 1, symbol_indexes[first_target], first_relocation_type),
        struct.pack("<IIH", 6, symbol_indexes[second_target], 0x14),
    ]
    if data_target is not None and not drop_data_relocation:
        helper_relocation_rows.append(
            struct.pack(
                "<IIH",
                data_relocation_offset,
                symbol_indexes[data_target],
                data_relocation_type,
            )
        )
    helper_relocations = b"".join(helper_relocation_rows)
    symbol_table = b"".join(symbols)
    symbol_offset = helper_relocation_offset + len(helper_relocations)
    header = struct.pack("<HHIIIHH", 0x14C, 2, 0xAABBCCDD, symbol_offset, len(symbols), 0, 0)
    retained_section = retained_section_name.encode("ascii").ljust(8, b"\0") + struct.pack(
        "<IIIIIIHHI",
        0,
        0,
        len(retained_body),
        retained_offset,
        retained_relocation_offset,
        0,
        1 if retained_reference is not None else 0,
        0,
        0x60501020,
    )
    helper_section = b".text\0\0\0" + struct.pack(
        "<IIIIIIHHI",
        0,
        0,
        len(helper_body),
        helper_offset,
        helper_relocation_offset,
        0,
        len(helper_relocation_rows),
        0,
        0x60501020,
    )
    string_table = struct.pack("<I", 4 + len(string_payload)) + string_payload
    return (
        header
        + retained_section
        + helper_section
        + retained_body
        + helper_body
        + retained_relocation
        + helper_relocations
        + symbol_table
        + string_table
    )


def _coff_symbol_offset(payload: bytes, name: str) -> int:
    symbol_offset, symbol_count = struct.unpack_from("<II", payload, 8)
    index = 0
    while index < symbol_count:
        offset = symbol_offset + index * 18
        raw_name = payload[offset : offset + 8].rstrip(b"\0").decode("ascii")
        auxiliary_count = payload[offset + 17]
        if raw_name == name:
            return offset
        index += 1 + auxiliary_count
    raise AssertionError(f"fixture symbol is absent: {name}")


def _patch_coff_symbol(
    payload: bytes,
    name: str,
    *,
    value: int | None = None,
    section: int | None = None,
) -> bytes:
    result = bytearray(payload)
    offset = _coff_symbol_offset(payload, name)
    if value is not None:
        struct.pack_into("<I", result, offset + 8, value)
    if section is not None:
        struct.pack_into("<h", result, offset + 12, section)
    return bytes(result)


def _patch_coff_symbol_name(payload: bytes, name: str, replacement: str) -> bytes:
    encoded = replacement.encode("ascii")
    assert len(encoded) <= 8
    result = bytearray(payload)
    offset = _coff_symbol_offset(payload, name)
    result[offset : offset + 8] = encoded.ljust(8, b"\0")
    return bytes(result)


def _append_coff_symbols(payload: bytes, *symbols: bytes) -> bytes:
    symbol_offset, symbol_count = struct.unpack_from("<II", payload, 8)
    string_table_offset = symbol_offset + symbol_count * 18
    result = bytearray(
        payload[:string_table_offset] + b"".join(symbols) + payload[string_table_offset:]
    )
    struct.pack_into("<I", result, 12, symbol_count + len(symbols))
    return bytes(result)


def _coff_object_with_external_code_entry(
    body: bytes,
    entry: int,
    *,
    via_owner_addend: bool = False,
) -> bytes:
    """Build one code COMDAT plus an ordinary data relocation into its body."""

    section_table_end = 20 + 2 * 40
    text_offset = section_table_end
    data = struct.pack("<I", entry) if via_owner_addend else bytes(4)
    data_offset = text_offset + len(body)
    relocation_offset = data_offset + len(data)
    symbols = (
        _symbol(".text", section=1, symbol_type=0, storage=3, auxiliary_count=1),
        struct.pack("<IHHIhBBH", len(body), 0, 0, 0, 0, 2, 0, 0),
        _symbol("_entry", section=1, symbol_type=32, storage=2),
        _symbol("$L1", value=entry, section=1, symbol_type=0, storage=3),
        _symbol(".rdata", section=2, symbol_type=0, storage=3, auxiliary_count=1),
        struct.pack("<IHHIhBBH", len(data), 1, 0, 0, 0, 0, 0, 0),
    )
    symbol_table = b"".join(symbols)
    symbol_offset = relocation_offset + 10
    header = struct.pack("<HHIIIHH", 0x14C, 2, 0xAABBCCDD, symbol_offset, len(symbols), 0, 0)
    text_section = b".text\0\0\0" + struct.pack(
        "<IIIIIIHHI",
        0,
        0,
        len(body),
        text_offset,
        0,
        0,
        0,
        0,
        0x60501020,
    )
    data_section = b".rdata\0\0" + struct.pack(
        "<IIIIIIHHI",
        0,
        0,
        len(data),
        data_offset,
        relocation_offset,
        0,
        1,
        0,
        0x40301040,
    )
    relocation = struct.pack("<IIH", 0, 2 if via_owner_addend else 3, 6)
    return (
        header
        + text_section
        + data_section
        + body
        + data
        + relocation
        + symbol_table
        + struct.pack("<I", 4)
    )


def _coff_object_with_relocated_text_tail(
    *,
    prefix_byte: int = 1,
    first_slot_offset: int = 24,
    first_slot_target: str = "$L1",
    first_slot_type: int = 6,
    first_slot_addend: int = 0,
    first_target_value: int = 12,
    include_second_slot: bool = True,
) -> bytes:
    """Build code followed by two relocation-backed words in ``.text``."""

    prefix = (
        bytes.fromhex("83f801 770d ff2485 00000000")
        + bytes((0xB8, prefix_byte, 0, 0, 0, 0xC3))
        + bytes.fromhex("b802000000 c3")
    )
    assert len(prefix) == 24
    body = bytearray(prefix + bytes(8))
    struct.pack_into("<I", body, first_slot_offset, first_slot_addend)
    section_table_end = 20 + 40
    relocation_offset = section_table_end + len(body)
    symbol_indexes = {
        "$L0": 3,
        "$L1": 4,
        "$L2": 5,
        "_ext1": 6,
        "_ext2": 7,
    }
    relocation_rows = [
        struct.pack("<IIH", 8, symbol_indexes["$L0"], 6),
        struct.pack(
            "<IIH",
            first_slot_offset,
            symbol_indexes[first_slot_target],
            first_slot_type,
        ),
    ]
    if include_second_slot:
        relocation_rows.append(struct.pack("<IIH", 28, symbol_indexes["$L2"], 6))
    relocations = b"".join(relocation_rows)
    symbols = (
        _symbol(".text", section=1, symbol_type=0, storage=3, auxiliary_count=1),
        struct.pack("<IHHIhBBH", len(body), len(relocation_rows), 0, 0, 0, 2, 0, 0),
        _symbol("_entry", section=1, symbol_type=32, storage=2),
        _symbol("$L0", value=24, section=1, symbol_type=0, storage=6),
        _symbol("$L1", value=first_target_value, section=1, symbol_type=0, storage=6),
        _symbol("$L2", value=18, section=1, symbol_type=0, storage=6),
        _symbol("_ext1", section=0, symbol_type=0, storage=2),
        _symbol("_ext2", section=0, symbol_type=0, storage=2),
    )
    symbol_table = b"".join(symbols)
    symbol_offset = relocation_offset + len(relocations)
    header = struct.pack("<HHIIIHH", 0x14C, 1, 0xAABBCCDD, symbol_offset, len(symbols), 0, 0)
    section = b".text\0\0\0" + struct.pack(
        "<IIIIIIHHI",
        0,
        0,
        len(body),
        section_table_end,
        relocation_offset,
        0,
        len(relocation_rows),
        0,
        0x60501020,
    )
    return header + section + bytes(body) + relocations + symbol_table + struct.pack("<I", 4)


def _coff_object_with_permutable_data_comdats(
    order: tuple[str, str],
    *,
    a_section_name: str = ".data",
    a_selection: int = 2,
    a_associated: int = 0,
    a_relocation: bool = False,
) -> bytes:
    """Build code referencing two independently selectable data COMDATs."""

    assert set(order) == {"a", "b"}
    bodies = {"a": b"A\0\0\0", "b": b"second"}
    section_names = {"a": a_section_name, "b": ".data"}
    selections = {"a": a_selection, "b": 2}
    associations = {"a": a_associated, "b": 0}
    text = b"\xa1\0\0\0\0\xa1\0\0\0\0\xc3"
    section_table_end = 20 + 3 * 40
    text_offset = section_table_end
    first_offset = text_offset + len(text)
    second_offset = first_offset + len(bodies[order[0]])
    data_end = second_offset + len(bodies[order[1]])
    text_relocation_offset = data_end

    symbols: list[bytes] = [
        _symbol(".text", section=1, symbol_type=0, storage=3, auxiliary_count=1),
        struct.pack("<IHHIhBBH", len(text), 2, 0, 0, 0, 2, 0, 0),
        _symbol("_entry", section=1, symbol_type=32, storage=2),
    ]
    owner_indexes: dict[str, int] = {}
    for section_number, key in enumerate(order, start=2):
        name = section_names[key]
        symbols.extend(
            [
                _symbol(
                    name,
                    section=section_number,
                    symbol_type=0,
                    storage=3,
                    auxiliary_count=1,
                ),
                struct.pack(
                    "<IHHIhBBH",
                    len(bodies[key]),
                    1 if a_relocation and key == "a" else 0,
                    0,
                    0,
                    associations[key],
                    selections[key],
                    0,
                    0,
                ),
            ]
        )
        owner_indexes[key] = len(symbols)
        symbols.append(_symbol(f"_{key}", section=section_number, symbol_type=0, storage=2))
    symbol_table = b"".join(symbols)
    data_relocation = struct.pack("<IIH", 0, owner_indexes["b"], 6) if a_relocation else b""
    data_relocation_offset = text_relocation_offset + 20 if a_relocation else 0
    symbol_offset = text_relocation_offset + 20 + len(data_relocation)
    header = struct.pack("<HHIIIHH", 0x14C, 3, 0xAABBCCDD, symbol_offset, len(symbols), 0, 0)
    text_section = b".text\0\0\0" + struct.pack(
        "<IIIIIIHHI",
        0,
        0,
        len(text),
        text_offset,
        text_relocation_offset,
        0,
        2,
        0,
        0x60501020,
    )
    data_sections: list[bytes] = []
    for index, key in enumerate(order):
        name = section_names[key]
        raw_offset = first_offset if index == 0 else second_offset
        relocation_offset = data_relocation_offset if key == "a" and a_relocation else 0
        data_sections.append(
            name.encode("ascii").ljust(8, b"\0")
            + struct.pack(
                "<IIIIIIHHI",
                0,
                0,
                len(bodies[key]),
                raw_offset,
                relocation_offset,
                0,
                1 if relocation_offset else 0,
                0,
                0xC0301040,
            )
        )
    text_relocations = b"".join(
        (
            struct.pack("<IIH", 1, owner_indexes["a"], 6),
            struct.pack("<IIH", 6, owner_indexes["b"], 6),
        )
    )
    return (
        header
        + text_section
        + b"".join(data_sections)
        + text
        + bodies[order[0]]
        + bodies[order[1]]
        + text_relocations
        + data_relocation
        + symbol_table
        + struct.pack("<I", 4)
    )


def _patch_comdat_auxiliary(
    payload: bytes,
    *,
    selection: int | None = None,
    associated: int | None = None,
) -> bytes:
    result = bytearray(payload)
    symbol_offset = struct.unpack_from("<I", payload, 8)[0]
    auxiliary_offset = symbol_offset + 18
    if selection is not None:
        result[auxiliary_offset + 14] = selection
    if associated is not None:
        struct.pack_into("<H", result, auxiliary_offset + 12, associated & 0xFFFF)
        struct.pack_into("<H", result, auxiliary_offset + 16, associated >> 16)
    return bytes(result)


def _add_coff_line_table(payload: bytes, records: tuple[tuple[int, int], ...]) -> bytes:
    """Insert structurally valid ``(value, line)`` records in section one."""

    assert records
    symbol_offset = struct.unpack_from("<I", payload, 8)[0]
    encoded = b"".join(struct.pack("<IH", value, line) for value, line in records)
    result = bytearray(payload[:symbol_offset] + encoded + payload[symbol_offset:])
    struct.pack_into("<I", result, 8, symbol_offset + len(encoded))
    struct.pack_into("<I", result, 48, symbol_offset)
    struct.pack_into("<H", result, 54, len(records))
    section_name = payload[20:28].rstrip(b"\0").decode("ascii")
    section_symbol_offset = _coff_symbol_offset(bytes(result), section_name)
    struct.pack_into("<H", result, section_symbol_offset + 18 + 6, len(records))
    return bytes(result)


def _add_coff_line_record(payload: bytes) -> bytes:
    """Insert one zero-line function-target record in section one."""

    return _add_coff_line_table(payload, ((0, 0),))


def _patch_coff_line_record(
    payload: bytes,
    record_index: int,
    *,
    value: int | None = None,
    line: int | None = None,
) -> bytes:
    result = bytearray(payload)
    line_offset = struct.unpack_from("<I", payload, 48)[0]
    assert line_offset
    at = line_offset + record_index * 6
    if value is not None:
        struct.pack_into("<I", result, at, value)
    if line is not None:
        struct.pack_into("<H", result, at + 4, line)
    return bytes(result)


def _weak_reference_object(*, characteristics: int) -> bytes:
    payload = _coff_object(
        "_main",
        reference="_weak",
        body_payload=b"\xe8\0\0\0\0\xc3",
        relocation_offset_in_section=1,
        relocation_type=20,
    )
    result = bytearray(payload)
    symbol_offset, symbol_count = struct.unpack_from("<II", result, 8)
    weak_offset = _coff_symbol_offset(payload, "_weak")
    result[weak_offset + 16] = 105
    result[weak_offset + 17] = 1
    string_offset = symbol_offset + symbol_count * 18
    auxiliary = struct.pack("<II", 2, characteristics) + bytes(10)
    result[string_offset:string_offset] = auxiliary
    struct.pack_into("<I", result, 12, symbol_count + 1)
    return bytes(result)


def _coff_archive(name: str, payload: bytes) -> bytes:
    encoded = name.encode("ascii") + b"/"
    header = (
        encoded.ljust(16, b" ")
        + b"0".ljust(12, b" ")
        + b"0".ljust(6, b" ")
        + b"0".ljust(6, b" ")
        + b"100644".ljust(8, b" ")
        + str(len(payload)).encode("ascii").ljust(10, b" ")
        + b"`\n"
    )
    return b"!<arch>\n" + header + payload + (b"\n" if len(payload) & 1 else b"")


def _classic_archive_auxless_section_anchor(
    section_name: str,
    *,
    optional_size: int,
    section_characteristics: int,
    machine: int = 0x014C,
    extra_metadata: str | None = None,
    optional_version: tuple[int, int, int, int] = (3, 10, 4, 0),
) -> bytes:
    optional = bytearray(optional_size)
    if optional_size:
        assert optional_size == 0x00E0
        linker_major, linker_minor, os_major, os_minor = optional_version
        struct.pack_into("<HBB", optional, 0, 0x010B, linker_major, linker_minor)
        struct.pack_into("<HH", optional, 40, os_major, os_minor)
        for offset, byte in {
            33: 0x10,
            37: 0x02,
            74: 0x10,
            77: 0x10,
            82: 0x10,
            85: 0x10,
            92: 0x10,
        }.items():
            optional[offset] = byte
    section_table_end = 20 + optional_size + 40
    body = b"\0"
    auxless = _symbol(section_name, section=1, symbol_type=0, storage=3)
    canonical = _symbol(
        section_name,
        section=1,
        symbol_type=0,
        storage=3,
        auxiliary_count=1,
    ) + struct.pack("<IHHIhBBH", len(body), 0, 0, 0, 0, 0, 0, 0)
    if extra_metadata is None:
        symbols = auxless
    elif extra_metadata == "auxless":
        symbols = auxless + auxless
    elif extra_metadata == "canonical-after":
        symbols = auxless + canonical
    else:
        raise AssertionError(f"unknown fixture metadata shape: {extra_metadata}")
    header = struct.pack(
        "<HHIIIHH",
        machine,
        1,
        0,
        section_table_end + len(body),
        len(symbols) // 18,
        optional_size,
        0x0100,
    )
    section = section_name.encode("ascii") + struct.pack(
        "<IIIIIIHHI",
        0,
        0,
        len(body),
        section_table_end,
        0,
        0,
        0,
        0,
        section_characteristics,
    )
    return header + bytes(optional) + section + body + symbols + struct.pack("<I", 4)


def _import_object(symbol: str, dll: str) -> bytes:
    data = symbol.encode("ascii") + b"\0" + dll.encode("ascii") + b"\0"
    return struct.pack("<HHHHIIHH", 0, 0xFFFF, 0, 0x14C, 7, len(data), 0, 4) + data


def test_import_object_parser_returns_a_strict_archive_member_disposition() -> None:
    payload = _import_object("_puts", "runtime.dll")

    receipt = parse_classic_import_object(payload, label="runtime.lib(puts.obj)")

    assert receipt is not None
    assert receipt.digest == Digest.from_bytes(payload)
    assert receipt.symbol == "_puts"
    assert receipt.dll == "runtime.dll"
    assert receipt.definitions == frozenset({"_puts", "__imp__puts"})
    assert parse_classic_import_object(_coff_object("_main"), label="main.obj") is None


def test_import_object_parser_rejects_a_malformed_recognized_header() -> None:
    payload = bytearray(_import_object("_puts", "runtime.dll"))
    payload[6:8] = struct.pack("<H", 0x8664)

    with pytest.raises(ClassicSemanticError, match="supported i386 import object"):
        parse_classic_import_object(bytes(payload), label="unsafe.lib(member.obj)")


def test_coff_directive_parser_returns_exact_closed_controls() -> None:
    body = (
        b"-defaultlib:LIBCMT /include:?forced@@3HA "
        b"-export:?entry@@YAXXZ /merge:.CRT=.data "
        b"/disallowlib:msvcrt.lib\0"
    )
    receipt = parse_classic_coff_directives(
        _coff_object("_dir", section_name=".drectve", body_payload=body),
        label="directives.obj",
    )

    assert receipt.tokens == (
        "-defaultlib:LIBCMT",
        "/include:?forced@@3HA",
        "-export:?entry@@YAXXZ",
        "/merge:.CRT=.data",
        "/disallowlib:msvcrt.lib",
    )
    assert receipt.default_libraries == ("LIBCMT",)
    assert receipt.include_symbols == ("?forced@@3HA",)
    assert receipt.export_symbols == ("?entry@@YAXXZ",)
    assert receipt.merge_sections == ((".CRT", ".data"),)
    assert receipt.disallowed_libraries == ("msvcrt.lib",)


@pytest.mark.parametrize(
    "body",
    (
        b"/alternatename:_left=_right ",
        b"/defaultlib:C:\\sdk\\runtime.lib ",
        b"@response.rsp ",
        b"/include:_root\xff ",
        b"/merge:.CRT=C:\\host ",
        b"/disallowlib:C:\\host\\runtime.lib ",
        b"/include:_root\0\0",
        b"/include:_root\0/export:_hidden ",
    ),
)
def test_coff_directive_parser_rejects_unknown_path_and_non_ascii_controls(
    body: bytes,
) -> None:
    with pytest.raises(ClassicSemanticError, match="directive"):
        parse_classic_coff_directives(
            _coff_object("_dir", section_name=".drectve", body_payload=body),
            label="unsafe.obj",
        )


def test_link_relevant_coff_projection_normalizes_only_timestamp_and_debug_state() -> None:
    runtime = _coff_object("_entry", body_payload=b"\x90\xc3")
    changed_timestamp = bytearray(runtime)
    struct.pack_into("<I", changed_timestamp, 4, 0x11223344)

    baseline = classic_link_relevant_coff_projection(runtime, label="baseline.obj")
    timestamp = classic_link_relevant_coff_projection(
        bytes(changed_timestamp), label="timestamp.obj"
    )

    assert baseline.object_digest != timestamp.object_digest
    assert baseline.projection_digest == timestamp.projection_digest
    assert baseline.normalizations == (
        "coff-time-date-stamp",
        "debug-section-bytes-relocations-and-symbols",
        "external-program-database",
    )

    debug_a = classic_link_relevant_coff_projection(
        _coff_object("_debug", section_name=".debug$S", body_payload=b"one"),
        label="debug-a.obj",
    )
    debug_b = classic_link_relevant_coff_projection(
        _coff_object("_debug", section_name=".debug$S", body_payload=b"two"),
        label="debug-b.obj",
    )
    assert debug_a.object_digest != debug_b.object_digest
    assert debug_a.projection_digest == debug_b.projection_digest
    assert debug_a.excluded_section_names == (".debug$S",)

    debug_with_lines = classic_link_relevant_coff_projection(
        _add_coff_line_record(_coff_object("_debug", section_name=".debug$S", body_payload=b"one")),
        label="debug-lines.obj",
    )
    assert debug_a.projection_digest == debug_with_lines.projection_digest


def test_link_relevant_coff_projection_binds_a_retained_line_number_table() -> None:
    baseline = classic_link_relevant_coff_projection(
        _coff_object("_entry"), label="no-line-table.obj"
    )
    payload = _add_coff_line_record(_coff_object("_entry"))
    with_lines = classic_link_relevant_coff_projection(payload, label="line-table.obj")

    assert baseline.projection_digest != with_lines.projection_digest
    sections = with_lines.statement["sections"]
    assert isinstance(sections, list)
    assert sections[0]["line_numbers"] == [
        {
            "line": 0,
            "target": ".text",
            "target_section": 1,
            "target_value": 0,
            "target_type": 0,
            "target_storage": 3,
        }
    ]


def test_runtime_projection_excludes_source_line_debug_metadata() -> None:
    baseline = _parse_coff(_coff_object("_entry"), "baseline.obj")
    with_lines = _parse_coff(
        _add_coff_line_table(_coff_object("_entry"), ((0, 0), (0, 37))),
        "with-lines.obj",
    )

    assert _runtime_projection(baseline) == _runtime_projection(with_lines)


@pytest.mark.parametrize(
    ("counterfactual_body", "effective_body"),
    (
        (
            b"\x3b\xc1\x74\x03\x83\xc0\x00\x83\xc1\x00\xc3",
            b"\x3b\xc8\x74\x03\x83\xc0\x00\x83\xc1\x00\xc3",
        ),
        (
            b"\x3b\x44\x24\x08\x74\x03\x83\xc0\x00\x83\xc1\x00\xc3",
            b"\x39\x44\x24\x08\x74\x03\x83\xc0\x00\x83\xc1\x00\xc3",
        ),
    ),
)
def test_runtime_projection_proves_equality_only_cmp_operand_reversal(
    counterfactual_body: bytes,
    effective_body: bytes,
) -> None:
    counterfactual = _parse_coff(
        _coff_object("_entry", body_payload=counterfactual_body),
        "counterfactual.obj",
    )
    effective = _parse_coff(
        _coff_object("_entry", body_payload=effective_body),
        "effective.obj",
    )

    assert _runtime_projection(counterfactual) != _runtime_projection(effective)
    assert _runtime_projection_equivalence(counterfactual, effective) == (
        True,
        False,
        "ia32-equality-compare-operand-reversal-flags-dead-v1",
    )


@pytest.mark.parametrize(
    "effective_body",
    (
        # The fallthrough observes the differing carry flag.
        b"\x3b\xc8\x74\x05\x72\x03\x83\xc0\x00\x83\xc1\x00\xc3",
        # The fallthrough materializes the differing flags before returning.
        b"\x3b\xc8\x74\x02\x9c\xc3\x83\xc1\x00\xc3",
        # JG observes sign/overflow rather than equality alone.
        b"\x3b\xc8\x7f\x03\x83\xc0\x00\x83\xc1\x00\xc3",
    ),
)
def test_runtime_projection_rejects_cmp_reversal_with_live_flags(
    effective_body: bytes,
) -> None:
    counterfactual_body = effective_body.replace(b"\x3b\xc8", b"\x3b\xc1", 1)
    counterfactual = _parse_coff(
        _coff_object("_entry", body_payload=counterfactual_body),
        "counterfactual.obj",
    )
    effective = _parse_coff(
        _coff_object("_entry", body_payload=effective_body),
        "effective.obj",
    )

    assert _runtime_projection_equivalence(counterfactual, effective) == (
        False,
        False,
        None,
    )


def test_runtime_projection_accepts_relocated_cmp_displacement_when_rewrite_is_disjoint() -> None:
    counterfactual = _parse_coff(
        _coff_object(
            "_entry",
            reference="_address",
            body_payload=b"\x3b\x05\0\0\0\0\x74\x03\x83\xc0\x00\x83\xc1\x00\xc3",
            relocation_offset_in_section=2,
        ),
        "counterfactual.obj",
    )
    effective = _parse_coff(
        _coff_object(
            "_entry",
            reference="_address",
            body_payload=b"\x39\x05\0\0\0\0\x74\x03\x83\xc0\x00\x83\xc1\x00\xc3",
            relocation_offset_in_section=2,
        ),
        "effective.obj",
    )

    assert _runtime_projection_equivalence(counterfactual, effective) == (
        True,
        False,
        "ia32-equality-compare-operand-reversal-flags-dead-v1",
    )


@pytest.mark.parametrize("via_owner_addend", (False, True))
def test_runtime_projection_rejects_external_entry_from_unrelated_data_section(
    via_owner_addend: bool,
) -> None:
    # The ordinary entry reaches CLC before ADC, so the compare's changed CF
    # is dead.  The .rdata relocation enters directly at ADC and bypasses that
    # kill, making CF live at an independently reachable entry.
    counterfactual_body = bytes.fromhex("3bc1 7405 f8 83d000 c3 c3")
    effective_body = bytes.fromhex("3bc8 7405 f8 83d000 c3 c3")
    counterfactual = _parse_coff(
        _coff_object_with_external_code_entry(
            counterfactual_body,
            5,
            via_owner_addend=via_owner_addend,
        ),
        "counterfactual.obj",
    )
    effective = _parse_coff(
        _coff_object_with_external_code_entry(
            effective_body,
            5,
            via_owner_addend=via_owner_addend,
        ),
        "effective.obj",
    )

    assert _runtime_projection_equivalence(counterfactual, effective) == (
        False,
        False,
        None,
    )


def test_runtime_projection_rejects_second_external_owner_in_function_body() -> None:
    counterfactual_body = bytes.fromhex("3bc1 7405 f8 83d000 c3 c3")
    effective_body = bytes.fromhex("3bc8 7405 f8 83d000 c3 c3")
    alternate_owner = _symbol(
        "_alt",
        value=5,
        section=1,
        symbol_type=32,
        storage=2,
    )
    counterfactual = _parse_coff(
        _append_coff_symbols(
            _coff_object("_entry", body_payload=counterfactual_body),
            alternate_owner,
        ),
        "counterfactual.obj",
    )
    effective = _parse_coff(
        _append_coff_symbols(
            _coff_object("_entry", body_payload=effective_body),
            alternate_owner,
        ),
        "effective.obj",
    )

    assert _runtime_projection_equivalence(counterfactual, effective) == (
        False,
        False,
        None,
    )


def test_runtime_projection_rejects_cmp_theorem_with_unbounded_computed_target() -> None:
    # The retained relocation names CLC at offset 6, but it is not a theorem
    # that EAX can target only that instruction.  A jump to ADC at offset 7
    # bypasses the kill and observes CMP's reversed carry flag.
    counterfactual_body = bytes.fromhex("3bc1 7400 ffe0 f8 83d000 c3")
    effective_body = bytes.fromhex("3bc8 7400 ffe0 f8 83d000 c3")
    counterfactual = _parse_coff(
        _coff_object_with_external_code_entry(counterfactual_body, 6),
        "counterfactual.obj",
    )
    effective = _parse_coff(
        _coff_object_with_external_code_entry(effective_body, 6),
        "effective.obj",
    )

    assert _runtime_projection_equivalence(counterfactual, effective) == (
        False,
        False,
        None,
    )


_REGISTER_TRANSPOSITION_CLEAN = bytes.fromhex(
    "56 57 8bf9 8b7004 8bcf 898604000000 c7470801000000 5f 5e c3"
)
_REGISTER_TRANSPOSITION_EFFECTIVE = bytes.fromhex(
    "56 57 8bf1 8b7804 8bce 898704000000 c7460801000000 5f 5e c3"
)


def test_runtime_projection_derives_minimal_two_register_transposition() -> None:
    counterfactual = _parse_coff(
        _coff_object("_entry", body_payload=_REGISTER_TRANSPOSITION_CLEAN),
        "counterfactual.obj",
    )
    effective = _parse_coff(
        _coff_object("_entry", body_payload=_REGISTER_TRANSPOSITION_EFFECTIVE),
        "effective.obj",
    )

    equivalence = _runtime_projection_equivalence_proof(counterfactual, effective)

    assert equivalence.equivalent is True
    assert equivalence.byte_equal is False
    assert equivalence.theorem == "ia32-two-register-transposition-dead-boundaries-v1"
    assert equivalence.proof is not None
    sections = equivalence.proof["sections"]
    assert isinstance(sections, list)
    assert sections[0]["mapping"] == {"edi": "esi", "esi": "edi"}
    assert sections[0]["region"] == {"start": 2, "end": 22}
    assert sections[0]["changed_offsets"] == [3, 5, 8, 10, 16]
    trace = _coff_compiler_congruence_trace(
        counterfactual,
        effective,
        excluded_effective_sections=frozenset(),
        projection_equivalence=equivalence,
    )
    assert "two-register-transposition-over-one-dead-boundary-region" in trace["allowed_deltas"]


@pytest.mark.parametrize("via_owner_addend", (False, True))
def test_register_transposition_rejects_retained_relocation_into_region(
    via_owner_addend: bool,
) -> None:
    counterfactual = _parse_coff(
        _coff_object_with_external_code_entry(
            _REGISTER_TRANSPOSITION_CLEAN,
            9,
            via_owner_addend=via_owner_addend,
        ),
        "counterfactual.obj",
    )
    effective = _parse_coff(
        _coff_object_with_external_code_entry(
            _REGISTER_TRANSPOSITION_EFFECTIVE,
            9,
            via_owner_addend=via_owner_addend,
        ),
        "effective.obj",
    )

    assert _runtime_projection_equivalence(counterfactual, effective) == (
        False,
        False,
        None,
    )


def test_register_transposition_allows_relocation_at_region_entry() -> None:
    counterfactual = _parse_coff(
        _coff_object_with_external_code_entry(_REGISTER_TRANSPOSITION_CLEAN, 2),
        "counterfactual.obj",
    )
    effective = _parse_coff(
        _coff_object_with_external_code_entry(_REGISTER_TRANSPOSITION_EFFECTIVE, 2),
        "effective.obj",
    )

    assert _runtime_projection_equivalence(counterfactual, effective) == (
        True,
        False,
        "ia32-two-register-transposition-dead-boundaries-v1",
    )


def test_register_transposition_rejects_live_registers_at_region_entry() -> None:
    # The changed MOVs consume both allocation registers before either is
    # defined inside the derived region, so incoming values are observable.
    counterfactual_body = bytes.fromhex("56 57 8bc6 8bc7 5f 5e c3")
    effective_body = bytes.fromhex("56 57 8bc7 8bc6 5f 5e c3")
    counterfactual = _parse_coff(
        _coff_object("_entry", body_payload=counterfactual_body),
        "counterfactual.obj",
    )
    effective = _parse_coff(
        _coff_object("_entry", body_payload=effective_body),
        "effective.obj",
    )

    assert _runtime_projection_equivalence(counterfactual, effective) == (
        False,
        False,
        None,
    )


def test_register_transposition_rejects_partial_mapping_image() -> None:
    partial = bytearray(_REGISTER_TRANSPOSITION_EFFECTIVE)
    partial[16] = _REGISTER_TRANSPOSITION_CLEAN[16]
    counterfactual = _parse_coff(
        _coff_object("_entry", body_payload=_REGISTER_TRANSPOSITION_CLEAN),
        "counterfactual.obj",
    )
    effective = _parse_coff(
        _coff_object("_entry", body_payload=bytes(partial)),
        "effective.obj",
    )

    assert _runtime_projection_equivalence(counterfactual, effective) == (
        False,
        False,
        None,
    )


def test_register_transposition_rejects_external_type_zero_alias() -> None:
    alias = _symbol("_alias", value=9, section=1, symbol_type=0, storage=2)
    counterfactual = _parse_coff(
        _append_coff_symbols(
            _coff_object("_entry", body_payload=_REGISTER_TRANSPOSITION_CLEAN),
            alias,
        ),
        "counterfactual.obj",
    )
    effective = _parse_coff(
        _append_coff_symbols(
            _coff_object("_entry", body_payload=_REGISTER_TRANSPOSITION_EFFECTIVE),
            alias,
        ),
        "effective.obj",
    )

    assert _runtime_projection_equivalence(counterfactual, effective) == (
        False,
        False,
        None,
    )


def test_register_transposition_rejects_computed_transfer_without_target_theorem() -> None:
    counterfactual_body = _REGISTER_TRANSPOSITION_CLEAN[:-1] + b"\xff\xe0"
    effective_body = _REGISTER_TRANSPOSITION_EFFECTIVE[:-1] + b"\xff\xe0"
    counterfactual = _parse_coff(
        _coff_object("_entry", body_payload=counterfactual_body),
        "counterfactual.obj",
    )
    effective = _parse_coff(
        _coff_object("_entry", body_payload=effective_body),
        "effective.obj",
    )

    assert _runtime_projection_equivalence(counterfactual, effective) == (
        False,
        False,
        None,
    )


def test_coff_envelope_alpha_normalizes_compiler_local_symbol_order() -> None:
    baseline = _append_coff_symbols(
        _coff_object("_entry"),
        _symbol("$L1", value=0, section=1, symbol_type=0, storage=3),
        _symbol("$L2", value=1, section=1, symbol_type=0, storage=3),
    )
    candidate = _append_coff_symbols(
        _coff_object("_entry"),
        _symbol("$L2", value=0, section=1, symbol_type=0, storage=3),
        _symbol("$L1", value=1, section=1, symbol_type=0, storage=3),
    )

    theorem = _coff_compiler_congruence_trace(
        _parse_coff(baseline, "baseline.obj"),
        _parse_coff(candidate, "candidate.obj"),
        excluded_effective_sections=frozenset(),
    )

    assert theorem["theorem"] == "closed-source-compiler-congruence-coff-envelope-v1"


def test_typed_crt_pull_admits_only_its_derived_dead_helper_dependency() -> None:
    clean = _parse_coff(_coff_object("_entry"), "counterfactual.obj")
    effective = _parse_coff(
        _coff_object_with_unreachable_helper_dependency(),
        "effective.obj",
    )
    excluded, _definitions = _helper_delta_sections(
        clean=clean,
        effective=effective,
        helper_identifiers=("_helper",),
    )
    dependencies = _crt_pull_linker_dependencies(
        clean=clean,
        effective=effective,
        excluded_sections=excluded,
        helper_identifiers=("_helper",),
    )

    trace = _coff_compiler_congruence_trace(
        clean,
        effective,
        excluded_effective_sections=excluded,
        crt_pull_dependencies=dependencies,
    )

    assert [item.name for item in dependencies] == ["_pull"]
    assert trace["crt_pull_linker_dependencies"] == [
        {
            "name": "_pull",
            "type": 32,
            "helper_sections": [2],
            "relocation_sites": [{"section": 2, "offset": 1, "type": 20, "addend": "00000000"}],
        }
    ]
    assert "typed-unreachable-crt-linker-dependency" in trace["allowed_deltas"]
    assert "all-other-undefined-dependencies" in trace["preserved"]


def test_non_crt_helper_cannot_claim_a_novel_linker_dependency() -> None:
    clean = _parse_coff(_coff_object("_entry"), "counterfactual.obj")
    effective = _parse_coff(
        _coff_object_with_unreachable_helper_dependency(),
        "effective.obj",
    )
    excluded, _definitions = _helper_delta_sections(
        clean=clean,
        effective=effective,
        helper_identifiers=("_helper",),
    )

    with pytest.raises(ClassicSemanticError, match="closed COFF semantic envelope"):
        _coff_compiler_congruence_trace(
            clean,
            effective,
            excluded_effective_sections=excluded,
        )


def test_runtime_linkage_ignores_debug_only_relocation_dependencies() -> None:
    debug = _parse_coff(
        _coff_object(
            "_debug",
            definition_type=0,
            reference="_dbgonly",
            section_name=".debug$S",
        ),
        "debug.obj",
    )

    linkage = _linkage_statement(debug, excluded_sections=frozenset())

    assert "_dbgonly" not in linkage["relocation_dependencies"]


def _ordered_archive_seed_evidence(
    effective_payload: bytes | None = None,
    *,
    clean_payload: bytes | None = None,
) -> tuple[
    _CoffObject,
    _CoffObject,
    frozenset[int],
    tuple[_OrderedArchiveSeedDependency, ...],
]:
    clean_payload = clean_payload or _coff_object("_entry")
    candidate_payload = effective_payload or _coff_object_with_ordered_archive_seed()
    clean = _parse_coff(clean_payload, "counterfactual.obj")
    effective = _parse_coff(candidate_payload, "effective.obj")
    excluded, _definitions = _helper_delta_sections(
        clean=clean,
        effective=effective,
        helper_identifiers=("SeedOrder",),
    )
    dependencies = _seed_order_dependencies(
        clean=clean,
        effective=effective,
        excluded_sections=excluded,
        seed_helpers=(("SeedOrder", "reverse_statement_order_msvc_4_20"),),
    )
    return clean, effective, excluded, dependencies


def test_seed_sequence_source_theorem_carries_only_the_fixed_msvc_420_policy() -> None:
    clean = b"void Entry() {}\n"
    leaf = {
        "function_identifier": "SeedOrder",
        "undefined_binding_order": "reverse_statement_order_msvc_4_20",
    }

    delta = _validate_unreachable_helper_leaf(
        kind="seed_seq",
        leaf=leaf,
        action="insert",
        claim=None,
        path="src/unit.cpp",
        clean_payload=clean,
        anchor_offsets=(len(clean),),
        token_census={"Entry": 1},
        introduced=frozenset(),
    )

    assert delta.identifier == "SeedOrder"
    assert delta.ordered_archive_seed_policy == "reverse_statement_order_msvc_4_20"
    assert not delta.crt_pull
    assert not delta.projection_required


@pytest.mark.parametrize(
    ("seat", "projection_required"),
    (
        (0, True),
        (len(b"int owner;"), False),
        (len(b"int owner;\n"), False),
    ),
)
def test_seed_sequence_projection_gate_stops_at_the_last_clean_token(
    seat: int,
    projection_required: bool,
) -> None:
    clean = b"int owner;\n"
    delta = _validate_unreachable_helper_leaf(
        kind="seed_seq",
        leaf={
            "function_identifier": "SeedOrder",
            "undefined_binding_order": "reverse_statement_order_msvc_4_20",
        },
        action="insert",
        claim=None,
        path="src/unit.cpp",
        clean_payload=clean,
        anchor_offsets=(seat,),
        token_census={"owner": 1},
        introduced=frozenset(),
    )

    assert delta.projection_required is projection_required


@pytest.mark.parametrize(
    "leaf",
    (
        {
            "function_identifier": "OtherSeed",
            "undefined_binding_order": "reverse_statement_order_msvc_4_20",
        },
        {
            "function_identifier": "SeedOrder",
            "undefined_binding_order": "source_statement_order",
        },
    ),
)
def test_seed_sequence_source_theorem_rejects_other_helper_or_order_policy(
    leaf: dict[str, str],
) -> None:
    clean = b"void Entry() {}\n"
    with pytest.raises(ClassicSemanticError, match="ordered archive seed theorem differs"):
        _validate_unreachable_helper_leaf(
            kind="seed_seq",
            leaf=leaf,
            action="insert",
            claim=None,
            path="src/unit.cpp",
            clean_payload=clean,
            anchor_offsets=(len(clean),),
            token_census={"Entry": 1},
            introduced=frozenset(),
        )


def test_typed_ordered_archive_seed_admits_only_exact_reverse_undefined_rows() -> None:
    clean, effective, excluded, dependencies = _ordered_archive_seed_evidence()
    trace = _coff_compiler_congruence_trace(
        clean,
        effective,
        excluded_effective_sections=excluded,
        ordered_archive_seed_dependencies=dependencies,
    )

    assert [item.name for item in dependencies] == ["_pull_a", "_pull_b"]
    assert [item.undefined_row_ordinal for item in dependencies] == [1, 0]
    assert [item.undefined_symbol_index for item in dependencies] == [7, 6]
    assert "typed-ordered-archive-seed-dependency" in trace["allowed_deltas"]
    assert "all-other-undefined-dependencies" in trace["preserved"]
    assert trace["ordered_archive_seed_dependencies"] == [
        {
            "theorem": "ordered-archive-seed-undefined-binding-v1",
            "helper_identifier": "SeedOrder",
            "helper_symbol": "?SeedOrder@@YAXXZ",
            "helper_section": 2,
            "policy": "reverse_statement_order_msvc_4_20",
            "binding_kind": "function-rel32",
            "name": name,
            "type": 32,
            "relocation_offset": offset,
            "relocation_type": 20,
            "addend": "00000000",
            "first_use_ordinal": first_use,
            "undefined_symbol_index": symbol_index,
            "undefined_row_ordinal": row_ordinal,
        }
        for name, offset, first_use, symbol_index, row_ordinal in (
            ("_pull_a", 1, 0, 7, 1),
            ("_pull_b", 6, 1, 6, 0),
        )
    ]


def test_tail_ordered_archive_seed_cannot_authorize_a_retained_code_delta() -> None:
    clean, effective, excluded, dependencies = _ordered_archive_seed_evidence(
        _coff_object_with_ordered_archive_seed(retained_payload=b"\x90")
    )

    with pytest.raises(ClassicSemanticError, match="closed COFF semantic envelope"):
        _coff_compiler_congruence_trace(
            clean,
            effective,
            excluded_effective_sections=excluded,
            ordered_archive_seed_dependencies=dependencies,
            compiler_state_projection_required=False,
        )


def test_typed_ordered_archive_seed_reverses_the_complete_mixed_binding_sequence() -> None:
    clean, effective, excluded, dependencies = _ordered_archive_seed_evidence(
        _coff_object_with_ordered_archive_seed(data_target="_existing_data")
    )
    trace = _coff_compiler_congruence_trace(
        clean,
        effective,
        excluded_effective_sections=excluded,
        ordered_archive_seed_dependencies=dependencies,
    )

    assert [item.name for item in dependencies] == [
        "_pull_a",
        "_pull_b",
        "_existing_data",
    ]
    assert [item.binding_kind for item in dependencies] == [
        "function-rel32",
        "function-rel32",
        "data-dir32",
    ]
    assert [item.undefined_row_ordinal for item in dependencies] == [2, 1, 0]
    rows = trace["ordered_archive_seed_dependencies"]
    assert isinstance(rows, list)
    assert rows[-1]["binding_kind"] == "data-dir32"
    assert rows[-1]["relocation_type"] == 6
    assert rows[-1]["type"] == 0


def test_ordered_archive_seed_rejects_an_unknown_binding_kind() -> None:
    clean, effective, excluded, dependencies = _ordered_archive_seed_evidence()

    with pytest.raises(ClassicSemanticError, match="unknown binding kinds"):
        _coff_compiler_congruence_trace(
            clean,
            effective,
            excluded_effective_sections=excluded,
            ordered_archive_seed_dependencies=(
                replace(dependencies[0], binding_kind="function-rel23"),  # type: ignore[arg-type]
                *dependencies[1:],
            ),
        )


def test_typed_helper_dependencies_cannot_share_a_linker_name_across_types() -> None:
    clean, effective, excluded, dependencies = _ordered_archive_seed_evidence()

    with pytest.raises(ClassicSemanticError, match="dependency names overlap"):
        _coff_compiler_congruence_trace(
            clean,
            effective,
            excluded_effective_sections=excluded,
            crt_pull_dependencies=(
                _CrtPullLinkerDependency(
                    name=dependencies[0].name,
                    symbol_type=0,
                    helper_sections=(dependencies[0].helper_section,),
                    relocation_sites=((dependencies[0].helper_section, 0, 6, "00000000"),),
                ),
            ),
            ordered_archive_seed_dependencies=dependencies,
        )


def test_ordered_archive_seed_rejects_a_moved_data_binding_seat() -> None:
    with pytest.raises(ClassicSemanticError, match="non-call or inexact data"):
        _ordered_archive_seed_evidence(
            _coff_object_with_ordered_archive_seed(
                data_target="_existing_data",
                data_relocation_offset=3,
            )
        )

    with pytest.raises(ClassicSemanticError, match="do not reverse first-use order"):
        _ordered_archive_seed_evidence(
            _coff_object_with_ordered_archive_seed(
                data_target="_existing_data",
                undefined_order=("_pull_b", "_existing_data", "_pull_a"),
            )
        )


def test_ordered_archive_seed_cannot_drop_the_data_binding_seat() -> None:
    clean, effective, excluded, dependencies = _ordered_archive_seed_evidence(
        _coff_object_with_ordered_archive_seed(
            data_target="_existing_data",
            drop_data_relocation=True,
        )
    )

    with pytest.raises(ClassicSemanticError, match="closed COFF semantic envelope"):
        _coff_compiler_congruence_trace(
            clean,
            effective,
            excluded_effective_sections=excluded,
            ordered_archive_seed_dependencies=dependencies,
        )


@pytest.mark.parametrize(
    "payload",
    (
        _coff_object_with_ordered_archive_seed(
            data_target="_existing_data", data_relocation_type=0x14
        ),
        _coff_object_with_ordered_archive_seed(data_target="_existing_data", data_addend=1),
        _coff_object_with_ordered_archive_seed(data_target="_existing_data", data_row_value=1),
        _coff_object_with_ordered_archive_seed(data_target="_existing_data", data_row_type=0x20),
        _coff_object_with_ordered_archive_seed(data_target="_existing_data", data_row_storage=105),
        _coff_object_with_ordered_archive_seed(
            data_target="_existing_data", data_row_auxiliary_count=1
        ),
    ),
)
def test_ordered_archive_seed_rejects_an_inexact_data_binding(payload: bytes) -> None:
    with pytest.raises(
        ClassicSemanticError,
        match=r"non-call or inexact data|lacks one exact undefined data row",
    ):
        _ordered_archive_seed_evidence(payload)


def test_ordered_archive_seed_cannot_hide_an_unrelocated_undefined_row() -> None:
    clean, effective, excluded, dependencies = _ordered_archive_seed_evidence(
        _coff_object_with_ordered_archive_seed(extra_undefined="_evil")
    )

    with pytest.raises(ClassicSemanticError, match="closed COFF semantic envelope"):
        _coff_compiler_congruence_trace(
            clean,
            effective,
            excluded_effective_sections=excluded,
            ordered_archive_seed_dependencies=dependencies,
        )


def test_ordered_archive_seed_rejects_swapped_undefined_row_order() -> None:
    payload = _coff_object_with_ordered_archive_seed(undefined_order=("_pull_a", "_pull_b"))

    with pytest.raises(ClassicSemanticError, match="do not reverse first-use order"):
        _ordered_archive_seed_evidence(payload)


@pytest.mark.parametrize(
    ("payload", "message"),
    (
        (_coff_object_with_ordered_archive_seed(first_relocation_type=6), "non-call"),
        (_coff_object_with_ordered_archive_seed(first_addend=1), "non-call"),
        (_coff_object_with_ordered_archive_seed(first_row_value=1), "non-call"),
        (_coff_object_with_ordered_archive_seed(first_row_type=0), "non-call"),
        (_coff_object_with_ordered_archive_seed(first_row_storage=105), "non-call"),
        (
            _coff_object_with_ordered_archive_seed(first_row_auxiliary_count=1),
            "lacks one exact undefined function row",
        ),
        (
            _coff_object_with_ordered_archive_seed(duplicate_first_row=True),
            "lacks one exact undefined function row",
        ),
        (_coff_object_with_ordered_archive_seed(second_target="_pull_a"), "2 relocation sites"),
    ),
)
def test_ordered_archive_seed_rejects_inexact_relocation_or_undefined_row(
    payload: bytes,
    message: str,
) -> None:
    with pytest.raises(ClassicSemanticError, match=message):
        _ordered_archive_seed_evidence(payload)


def test_ordered_archive_seed_rejects_a_dependency_referenced_by_retained_code() -> None:
    with pytest.raises(ClassicSemanticError, match="referenced outside SeedOrder"):
        _ordered_archive_seed_evidence(
            _coff_object_with_ordered_archive_seed(retained_reference="_pull_a")
        )


def _function_auxiliary_receipt(payload: bytes) -> dict[str, object]:
    coff = _parse_coff(payload, "provider.obj")
    symbol = next(item for item in coff.symbols if item.name == "_pull_a")
    return _msvc_function_auxiliary_receipt(
        coff,
        symbol=symbol,
        section=coff.sections[symbol.section - 1],
    )


@pytest.mark.parametrize(
    ("next_definition", "next_index", "next_symbol"),
    ((None, 0, None), ("_later", 6, "_later")),
)
def test_msvc_function_auxiliary_binds_the_canonical_line_and_function_chain(
    next_definition: str | None,
    next_index: int,
    next_symbol: str | None,
) -> None:
    receipt = _function_auxiliary_receipt(
        _coff_function_provider_with_auxiliary(
            "_pull_a",
            next_definition=next_definition,
        )
    )

    assert receipt == {
        "kind": "msvc-function-definition",
        "tag_index": 4,
        "begin_source_line": 11,
        "total_size": 2,
        "line_pointer": 62,
        "line_zero_symbol_index": 2,
        "next_function_index": next_index,
        "next_function_symbol": next_symbol,
    }


@pytest.mark.parametrize(
    "changes",
    (
        {"line_pointer_delta": 1},
        {"line_zero_target_index": 0},
        {"next_definition": "_later", "next_function_index": 2},
        {"next_definition": "_later", "begin_next_tag_index": 4},
    ),
)
def test_msvc_function_auxiliary_rejects_an_inexact_canonical_binding(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ClassicSemanticError, match="inexact auxiliary"):
        _function_auxiliary_receipt(_coff_function_provider_with_auxiliary("_pull_a", **changes))


def _ordered_archive_seed_isolation_trace(
    *,
    linker_inputs: tuple[str, ...] | None = None,
    archives: tuple[ArchiveInput, ...] | None = None,
    extra_products: tuple[CompilerProduct, ...] = (),
    demand_root_symbols: tuple[str, ...] = (),
    retention_root_symbols: tuple[str, ...] = (),
    data_target: str | None = None,
    owner_directive: bytes | None = None,
) -> dict[str, object]:
    helper_node = "compiler.app.0000"
    helper_object_ref = "build/obj/seed.obj"
    archive_a = "system-library/a.lib"
    archive_b = "system-library/b.lib"
    effective_payload = _coff_object_with_ordered_archive_seed(
        data_target=data_target,
        retained_payload=owner_directive,
        retained_section_name=".drectve" if owner_directive is not None else ".text",
    )
    clean, effective, excluded, dependencies = _ordered_archive_seed_evidence(
        effective_payload,
        clean_payload=(
            _coff_object(
                "_entry",
                section_name=".drectve",
                body_payload=owner_directive,
            )
            if owner_directive is not None
            else None
        ),
    )
    selected_archives = archives or (
        ArchiveInput(archive_a, _coff_archive("a.obj", _coff_object("_pull_a"))),
        ArchiveInput(archive_b, _coff_archive("b.obj", _coff_object("_pull_b"))),
        *(
            (
                ArchiveInput(
                    "system-library/data.lib",
                    _coff_archive(
                        "data.obj",
                        _coff_object(data_target, definition_type=0),
                    ),
                ),
            )
            if data_target is not None
            else ()
        ),
    )
    products = {
        helper_node: CompilerProduct(
            helper_node,
            "source/src/seed.cpp",
            helper_object_ref,
            effective_payload,
        ),
        **{product.node_id: product for product in extra_products},
    }
    effective_objects = {
        helper_node: effective,
        **{
            product.node_id: _parse_coff(product.payload, product.object_ref)
            for product in extra_products
        },
    }
    compiler_nodes = tuple(sorted(products, key=str.casefold))
    archive_refs = tuple(
        sorted({archive.archive_ref for archive in selected_archives}, key=str.casefold)
    )
    return _helper_isolation_trace(
        target=TargetLinkClosure(
            "program",
            compiler_nodes,
            archive_refs,
            selected_archives,
            demand_root_symbols,
            retention_root_symbols,
        ),
        linker_inputs=linker_inputs
        or (
            helper_object_ref,
            archive_a,
            archive_b,
            *(("system-library/data.lib",) if data_target is not None else ()),
        ),
        products=products,
        counterfactual_objects={helper_node: clean},
        effective_objects=effective_objects,
        helper_sections={helper_node: excluded},
        crt_pull_dependencies={},
        ordered_archive_seed_dependencies={helper_node: dependencies},
    )


def test_ordered_archive_seed_records_exact_object_library_and_member_ordinals() -> None:
    trace = _ordered_archive_seed_isolation_trace(
        linker_inputs=(
            "build/obj/seed.obj",
            "build/res/app.res",
            "system-library/a.lib",
            "system-library/b.lib",
            "system-library/a.lib",
        )
    )

    dependencies = trace["ordered_archive_seed_dependencies"]
    assert isinstance(dependencies, list)
    first = dependencies[0]
    second = dependencies[1]
    assert first["owner"] == {
        "object_ref": "build/obj/seed.obj",
        "linker_input_ordinal": 0,
        "direct_object_ordinal": 0,
    }
    assert first["provider"] == {
        "archive_ref": "system-library/a.lib",
        "all_linker_input_ordinals": [2, 4],
        "all_library_occurrence_ordinals": [0, 2],
        "eligible_linker_input_ordinals": [2, 4],
        "eligible_library_occurrence_ordinals": [0, 2],
        "selected_linker_input_ordinal": 2,
        "selected_library_occurrence_ordinal": 0,
        "member_ordinal": 0,
        "member_name": "a.obj",
        "member_digest": Digest.from_bytes(_coff_object("_pull_a")).value,
        "function_definition_auxiliary": {"kind": "absent"},
    }
    assert second["provider"]["all_linker_input_ordinals"] == [3]
    assert second["provider"]["all_library_occurrence_ordinals"] == [1]
    assert trace["ordered_archive_seed_extraction_closure"] == (
        "locked-terminal-linker-and-literal-byte-verification"
    )


def _seed_data_reference_product(
    *, relocation_type: int = 0x06, relocate: bool = True
) -> CompilerProduct:
    return CompilerProduct(
        "compiler.app.0001",
        "source/src/reference.cpp",
        "build/obj/reference.obj",
        _coff_object(
            "_base",
            reference="_seedvar",
            body_payload=b"\xa1\0\0\0\0\xc3",
            relocation_offset_in_section=1,
            relocation_type=relocation_type,
            relocate_reference=relocate,
        ),
    )


def _mixed_seed_archives(
    *,
    data_provider_payloads: tuple[bytes, ...] = (_coff_object("_seedvar", definition_type=0),),
    import_provider: bool = False,
) -> tuple[ArchiveInput, ...]:
    archives = [
        ArchiveInput(
            "system-library/a.lib",
            _coff_archive("a.obj", _coff_object("_pull_a")),
        ),
        ArchiveInput(
            "system-library/b.lib",
            _coff_archive("b.obj", _coff_object("_pull_b")),
        ),
    ]
    archives.extend(
        ArchiveInput(
            f"system-library/data{index}.lib",
            _coff_archive("data.obj", payload),
        )
        for index, payload in enumerate(data_provider_payloads)
    )
    if import_provider:
        archives.append(
            ArchiveInput(
                "system-library/data-import.lib",
                _coff_archive("data.imp", _import_object("_seedvar", "runtime.dll")),
            )
        )
    return tuple(archives)


def test_mixed_ordered_archive_seed_records_exact_data_binding_evidence() -> None:
    trace = _ordered_archive_seed_isolation_trace(
        data_target="_seedvar",
        extra_products=(_seed_data_reference_product(),),
        archives=_mixed_seed_archives(),
        linker_inputs=(
            "build/obj/seed.obj",
            "build/obj/reference.obj",
            "system-library/a.lib",
            "system-library/b.lib",
            "system-library/data0.lib",
        ),
    )

    dependencies = trace["ordered_archive_seed_dependencies"]
    assert isinstance(dependencies, list)
    assert [item["binding_kind"] for item in dependencies] == [
        "function-rel32",
        "function-rel32",
        "data-dir32",
    ]
    data = dependencies[-1]
    assert data["first_use_ordinal"] == 2
    assert data["undefined_row_ordinal"] == 0
    assert data["retained_demand_order"] == {
        "first_linker_input_ordinal": 1,
        "relative_to_seed_owner": "after",
    }
    demand = data["retained_linker_demands"][0]
    assert demand["linker_input_ordinals"] == [1]
    assert demand["direct_object_ordinals"] == [1]
    assert demand["undefined_external_row"]["relocation_sites"] == [
        {
            "section": 1,
            "section_name": ".text",
            "offset": 1,
            "type": 6,
            "addend": "00000000",
        }
    ]
    assert data["provider"]["archive_ref"] == "system-library/data0.lib"
    assert data["provider"]["selected_linker_input_ordinal"] == 4
    assert data["provider"]["selected_library_occurrence_ordinal"] == 2
    assert data["provider"]["member_ordinal"] == 0


def test_ordered_archive_seed_data_owner_is_the_first_runtime_reference() -> None:
    with pytest.raises(ClassicSemanticError, match="demand before its SeedOrder owner"):
        _ordered_archive_seed_isolation_trace(
            data_target="_seedvar",
            extra_products=(_seed_data_reference_product(),),
            archives=_mixed_seed_archives(),
            linker_inputs=(
                "build/obj/reference.obj",
                "build/obj/seed.obj",
                "system-library/a.lib",
                "system-library/b.lib",
                "system-library/data0.lib",
            ),
        )


def test_ordered_archive_seed_data_selects_the_first_provider_after_owner() -> None:
    trace = _ordered_archive_seed_isolation_trace(
        data_target="_seedvar",
        extra_products=(_seed_data_reference_product(),),
        archives=_mixed_seed_archives(),
        linker_inputs=(
            "system-library/data0.lib",
            "build/obj/seed.obj",
            "build/obj/reference.obj",
            "system-library/a.lib",
            "system-library/b.lib",
            "system-library/data0.lib",
        ),
    )

    data = trace["ordered_archive_seed_dependencies"][-1]
    assert data["provider"]["all_linker_input_ordinals"] == [0, 5]
    assert data["provider"]["selected_linker_input_ordinal"] == 5


def test_ordered_archive_seed_data_binding_requires_retained_demand() -> None:
    with pytest.raises(ClassicSemanticError, match="no retained direct-object demand"):
        _ordered_archive_seed_isolation_trace(
            data_target="_seedvar",
            archives=_mixed_seed_archives(),
            linker_inputs=(
                "build/obj/seed.obj",
                "system-library/a.lib",
                "system-library/b.lib",
                "system-library/data0.lib",
            ),
        )

    trace = _ordered_archive_seed_isolation_trace(
        data_target="_seedvar",
        extra_products=(_seed_data_reference_product(relocation_type=0x14),),
        archives=_mixed_seed_archives(),
        linker_inputs=(
            "build/obj/seed.obj",
            "build/obj/reference.obj",
            "system-library/a.lib",
            "system-library/b.lib",
            "system-library/data0.lib",
        ),
    )
    assert (
        trace["ordered_archive_seed_dependencies"][-1]["retained_linker_demands"][0][
            "undefined_external_row"
        ]["relocation_sites"][0]["type"]
        == 0x14
    )


def test_ordered_archive_seed_accepts_an_unrelocated_undefined_demand_row() -> None:
    trace = _ordered_archive_seed_isolation_trace(
        data_target="_seedvar",
        extra_products=(_seed_data_reference_product(relocate=False),),
        archives=_mixed_seed_archives(),
        linker_inputs=(
            "build/obj/seed.obj",
            "build/obj/reference.obj",
            "system-library/a.lib",
            "system-library/b.lib",
            "system-library/data0.lib",
        ),
    )

    demand = trace["ordered_archive_seed_dependencies"][-1]["retained_linker_demands"][0][
        "undefined_external_row"
    ]
    assert demand["relocation_sites"] == []


def test_ordered_archive_seed_data_binding_rejects_direct_and_import_definitions() -> None:
    direct_provider = CompilerProduct(
        "compiler.app.0002",
        "source/src/provider.cpp",
        "build/obj/provider.obj",
        _coff_object("_seedvar", definition_type=0),
    )
    with pytest.raises(ClassicSemanticError, match="has a direct object definition"):
        _ordered_archive_seed_isolation_trace(
            data_target="_seedvar",
            extra_products=(_seed_data_reference_product(), direct_provider),
            archives=_mixed_seed_archives(),
            linker_inputs=(
                "build/obj/seed.obj",
                "build/obj/reference.obj",
                "build/obj/provider.obj",
                "system-library/a.lib",
                "system-library/b.lib",
                "system-library/data0.lib",
            ),
        )

    with pytest.raises(ClassicSemanticError, match="has an import definition"):
        _ordered_archive_seed_isolation_trace(
            data_target="_seedvar",
            extra_products=(_seed_data_reference_product(),),
            archives=_mixed_seed_archives(import_provider=True),
            linker_inputs=(
                "build/obj/seed.obj",
                "build/obj/reference.obj",
                "system-library/a.lib",
                "system-library/b.lib",
                "system-library/data0.lib",
                "system-library/data-import.lib",
            ),
        )


@pytest.mark.parametrize("provider_count", (0, 2))
def test_ordered_archive_seed_data_binding_requires_one_archive_provider(
    provider_count: int,
) -> None:
    archives = _mixed_seed_archives(
        data_provider_payloads=tuple(
            _coff_object("_seedvar", definition_type=0) for _index in range(provider_count)
        )
    )
    linker_inputs = (
        "build/obj/seed.obj",
        "build/obj/reference.obj",
        "system-library/a.lib",
        "system-library/b.lib",
        *(f"system-library/data{index}.lib" for index in range(provider_count)),
    )
    with pytest.raises(
        ClassicSemanticError,
        match=rf"_seedvar.*has {provider_count} ordinary archive providers",
    ):
        _ordered_archive_seed_isolation_trace(
            data_target="_seedvar",
            extra_products=(_seed_data_reference_product(),),
            archives=archives,
            linker_inputs=linker_inputs,
        )


def test_ordered_archive_seed_data_binding_rejects_wrong_provider_type_and_order() -> None:
    with pytest.raises(ClassicSemanticError, match="inexact typed archive provider"):
        _ordered_archive_seed_isolation_trace(
            data_target="_seedvar",
            extra_products=(_seed_data_reference_product(),),
            archives=_mixed_seed_archives(
                data_provider_payloads=(_coff_object("_seedvar", definition_type=0x20),)
            ),
            linker_inputs=(
                "build/obj/seed.obj",
                "build/obj/reference.obj",
                "system-library/a.lib",
                "system-library/b.lib",
                "system-library/data0.lib",
            ),
        )

    with pytest.raises(ClassicSemanticError, match="has no occurrence after owner"):
        _ordered_archive_seed_isolation_trace(
            data_target="_seedvar",
            extra_products=(_seed_data_reference_product(),),
            archives=_mixed_seed_archives(),
            linker_inputs=(
                "system-library/data0.lib",
                "build/obj/seed.obj",
                "build/obj/reference.obj",
                "system-library/a.lib",
                "system-library/b.lib",
            ),
        )


def test_ordered_archive_seed_data_binding_rejects_a_linker_root() -> None:
    with pytest.raises(ClassicSemanticError, match="initial demand linker root"):
        _ordered_archive_seed_isolation_trace(
            data_target="_seedvar",
            extra_products=(_seed_data_reference_product(),),
            archives=_mixed_seed_archives(),
            demand_root_symbols=("_seedvar",),
            linker_inputs=(
                "build/obj/seed.obj",
                "build/obj/reference.obj",
                "system-library/a.lib",
                "system-library/b.lib",
                "system-library/data0.lib",
            ),
        )


def test_ordered_archive_seed_accepts_a_provider_compiler_embedded_only_in_an_archive() -> None:
    provider_payload = _coff_object("_pull_a")
    provider = CompilerProduct(
        "compiler.app.0001",
        "source/src/provider.cpp",
        "build/obj/provider.obj",
        provider_payload,
    )

    trace = _ordered_archive_seed_isolation_trace(
        extra_products=(provider,),
        archives=(
            ArchiveInput(
                "system-library/a.lib",
                _coff_archive("provider.obj", provider_payload),
            ),
            ArchiveInput(
                "system-library/b.lib",
                _coff_archive("b.obj", _coff_object("_pull_b")),
            ),
        ),
    )

    dependencies = trace["ordered_archive_seed_dependencies"]
    assert isinstance(dependencies, list)
    assert dependencies[0]["provider"]["member_name"] == "provider.obj"


def test_ordered_archive_seed_rejects_the_same_provider_as_a_direct_object() -> None:
    provider_payload = _coff_object("_pull_a")
    provider = CompilerProduct(
        "compiler.app.0001",
        "source/src/provider.cpp",
        "build/obj/provider.obj",
        provider_payload,
    )

    with pytest.raises(ClassicSemanticError, match="resolves before ordinary archive extraction"):
        _ordered_archive_seed_isolation_trace(
            extra_products=(provider,),
            linker_inputs=(
                "build/obj/seed.obj",
                "build/obj/provider.obj",
                "system-library/a.lib",
                "system-library/b.lib",
            ),
        )


@pytest.mark.parametrize("relocation_type", (0x06, 0x14))
def test_ordered_archive_seed_accepts_a_later_typed_baseline_reference(
    relocation_type: int,
) -> None:
    reference_payload = _coff_object(
        "_other",
        reference="_pull_a",
        reference_type=0x20,
        body_payload=b"\xe8\0\0\0\0\xc3",
        relocation_offset_in_section=1,
        relocation_type=relocation_type,
    )
    reference_product = CompilerProduct(
        "compiler.app.0001",
        "source/src/reference.cpp",
        "build/obj/reference.obj",
        reference_payload,
    )

    trace = _ordered_archive_seed_isolation_trace(
        extra_products=(reference_product,),
        linker_inputs=(
            "build/obj/seed.obj",
            "build/obj/reference.obj",
            "system-library/a.lib",
            "system-library/b.lib",
        ),
    )

    dependency = trace["ordered_archive_seed_dependencies"][0]
    assert dependency["retained_demand_order"] == {
        "first_linker_input_ordinal": 1,
        "relative_to_seed_owner": "after",
    }
    assert (
        dependency["retained_linker_demands"][0]["undefined_external_row"]["relocation_sites"][0][
            "type"
        ]
        == relocation_type
    )


def test_ordered_archive_seed_accepts_a_later_unrelocated_function_demand_row() -> None:
    reference_payload = _coff_object(
        "_other",
        reference="_pull_a",
        reference_type=0x20,
        relocate_reference=False,
    )
    reference_product = CompilerProduct(
        "compiler.app.0001",
        "source/src/reference.cpp",
        "build/obj/reference.obj",
        reference_payload,
    )

    trace = _ordered_archive_seed_isolation_trace(
        extra_products=(reference_product,),
        linker_inputs=(
            "build/obj/seed.obj",
            "build/obj/reference.obj",
            "system-library/a.lib",
            "system-library/b.lib",
        ),
    )

    demand = trace["ordered_archive_seed_dependencies"][0]["retained_linker_demands"][0][
        "undefined_external_row"
    ]
    assert demand["symbol_index"] == 3
    assert demand["relocation_sites"] == []


def test_ordered_archive_seed_rejects_an_earlier_baseline_reference() -> None:
    reference_product = CompilerProduct(
        "compiler.app.0001",
        "source/src/reference.cpp",
        "build/obj/reference.obj",
        _coff_object(
            "_other",
            reference="_pull_a",
            reference_type=0x20,
            body_payload=b"\xe8\0\0\0\0\xc3",
            relocation_offset_in_section=1,
            relocation_type=0x14,
        ),
    )

    with pytest.raises(ClassicSemanticError, match="demand before its SeedOrder owner"):
        _ordered_archive_seed_isolation_trace(
            extra_products=(reference_product,),
            linker_inputs=(
                "build/obj/reference.obj",
                "build/obj/seed.obj",
                "system-library/a.lib",
                "system-library/b.lib",
            ),
        )


def test_ordered_archive_seed_rejects_an_import_provider() -> None:
    with pytest.raises(ClassicSemanticError, match="resolves before ordinary archive extraction"):
        _ordered_archive_seed_isolation_trace(
            archives=(
                ArchiveInput(
                    "system-library/a.lib",
                    _coff_archive("a.imp", _import_object("_pull_a", "runtime.dll")),
                ),
                ArchiveInput(
                    "system-library/b.lib",
                    _coff_archive("b.obj", _coff_object("_pull_b")),
                ),
            )
        )


@pytest.mark.parametrize("provider_count", (0, 2))
def test_ordered_archive_seed_requires_one_ordinary_archive_provider(
    provider_count: int,
) -> None:
    archives = [
        ArchiveInput(
            "system-library/b.lib",
            _coff_archive("b.obj", _coff_object("_pull_b")),
        )
    ]
    linker_inputs = ["build/obj/seed.obj", "system-library/b.lib"]
    for index in range(provider_count):
        reference = f"system-library/a{index}.lib"
        archives.append(ArchiveInput(reference, _coff_archive("a.obj", _coff_object("_pull_a"))))
        linker_inputs.append(reference)

    with pytest.raises(
        ClassicSemanticError,
        match=rf"_pull_a.*has {provider_count} ordinary archive providers",
    ):
        _ordered_archive_seed_isolation_trace(
            linker_inputs=tuple(linker_inputs),
            archives=tuple(archives),
        )


def test_ordered_archive_seed_requires_provider_archive_after_owner_object() -> None:
    with pytest.raises(ClassicSemanticError, match="has no occurrence after owner"):
        _ordered_archive_seed_isolation_trace(
            linker_inputs=(
                "system-library/a.lib",
                "build/obj/seed.obj",
                "system-library/b.lib",
            )
        )


def test_ordered_archive_seed_accepts_a_retention_root() -> None:
    trace = _ordered_archive_seed_isolation_trace(retention_root_symbols=("_pull_a",))

    dependencies = trace["ordered_archive_seed_dependencies"]
    assert dependencies[0]["retention_linker_root"] is True
    assert dependencies[1]["retention_linker_root"] is False


def test_ordered_archive_seed_rejects_an_initial_demand_root() -> None:
    with pytest.raises(ClassicSemanticError, match="initial demand linker root"):
        _ordered_archive_seed_isolation_trace(demand_root_symbols=("_pull_a",))


def test_ordered_archive_seed_records_a_later_directive_demand() -> None:

    directive_payload = _coff_object(
        "_dir",
        section_name=".drectve",
        body_payload=b"/include:_pull_a",
    )
    directive_product = CompilerProduct(
        "compiler.app.0001",
        "source/src/directive.cpp",
        "build/obj/directive.obj",
        directive_payload,
    )
    trace = _ordered_archive_seed_isolation_trace(
        extra_products=(directive_product,),
        linker_inputs=(
            "build/obj/seed.obj",
            "build/obj/directive.obj",
            "system-library/a.lib",
            "system-library/b.lib",
        ),
    )

    dependencies = trace["ordered_archive_seed_dependencies"]
    assert dependencies[0]["retained_demand_order"] == {
        "first_linker_input_ordinal": 1,
        "relative_to_seed_owner": "after",
    }
    demand = dependencies[0]["retained_linker_demands"][0]
    assert demand["undefined_external_row"] is None
    assert demand["include_directive_count"] == 1


def test_ordered_archive_seed_rejects_an_earlier_directive_demand() -> None:
    directive_product = CompilerProduct(
        "compiler.app.0001",
        "source/src/directive.cpp",
        "build/obj/directive.obj",
        _coff_object(
            "_dir",
            section_name=".drectve",
            body_payload=b"/include:_pull_a",
        ),
    )

    with pytest.raises(ClassicSemanticError, match="demand before its SeedOrder owner"):
        _ordered_archive_seed_isolation_trace(
            extra_products=(directive_product,),
            linker_inputs=(
                "build/obj/directive.obj",
                "build/obj/seed.obj",
                "system-library/a.lib",
                "system-library/b.lib",
            ),
        )


def test_ordered_archive_seed_rejects_same_input_directive_demand() -> None:
    with pytest.raises(ClassicSemanticError, match="same input"):
        _ordered_archive_seed_isolation_trace(
            owner_directive=b"/INCLUDE:_pull_a",
        )


def test_ordered_archive_seed_treats_export_as_retention_only() -> None:
    trace = _ordered_archive_seed_isolation_trace(
        owner_directive=b"/EXPORT:_pull_a",
    )

    dependency = trace["ordered_archive_seed_dependencies"][0]
    assert dependency["retention_linker_root"] is True
    assert dependency["retained_linker_demands"] == []


def test_ordered_archive_seed_owner_must_have_one_direct_linker_occurrence() -> None:
    with pytest.raises(ClassicSemanticError, match="has 2 direct linker occurrences"):
        _ordered_archive_seed_isolation_trace(
            linker_inputs=(
                "build/obj/seed.obj",
                "build/obj/seed.obj",
                "system-library/a.lib",
                "system-library/b.lib",
            )
        )


def test_crt_pull_cannot_hide_an_unrelocated_extra_undefined() -> None:
    clean = _parse_coff(_coff_object("_entry"), "counterfactual.obj")
    effective = _parse_coff(
        _coff_object_with_unreachable_helper_dependency(extra_undefined="_evil"),
        "effective.obj",
    )
    excluded, _definitions = _helper_delta_sections(
        clean=clean,
        effective=effective,
        helper_identifiers=("_helper",),
    )
    dependencies = _crt_pull_linker_dependencies(
        clean=clean,
        effective=effective,
        excluded_sections=excluded,
        helper_identifiers=("_helper",),
    )

    with pytest.raises(ClassicSemanticError, match="closed COFF semantic envelope"):
        _coff_compiler_congruence_trace(
            clean,
            effective,
            excluded_effective_sections=excluded,
            crt_pull_dependencies=dependencies,
        )


def test_crt_pull_rejects_a_dependency_referenced_by_retained_code() -> None:
    clean = _parse_coff(_coff_object("_entry"), "counterfactual.obj")
    effective = _parse_coff(
        _coff_object_with_unreachable_helper_dependency(retained_reference=True),
        "effective.obj",
    )
    excluded, _definitions = _helper_delta_sections(
        clean=clean,
        effective=effective,
        helper_identifiers=("_helper",),
    )

    with pytest.raises(ClassicSemanticError, match="referenced outside its helpers"):
        _crt_pull_linker_dependencies(
            clean=clean,
            effective=effective,
            excluded_sections=excluded,
            helper_identifiers=("_helper",),
        )


def test_crt_pull_records_a_declared_ordinary_archive_provider_candidate() -> None:
    clean_payload = _coff_object("_entry")
    effective_payload = _coff_object_with_unreachable_helper_dependency()
    clean = _parse_coff(clean_payload, "counterfactual.obj")
    effective = _parse_coff(effective_payload, "effective.obj")
    excluded, _definitions = _helper_delta_sections(
        clean=clean,
        effective=effective,
        helper_identifiers=("_helper",),
    )
    dependencies = _crt_pull_linker_dependencies(
        clean=clean,
        effective=effective,
        excluded_sections=excluded,
        helper_identifiers=("_helper",),
    )
    node_id = "compiler.app.0000"
    archive_ref = "system-library/runtime.lib"
    trace = _helper_isolation_trace(
        target=TargetLinkClosure(
            "program",
            (node_id,),
            (archive_ref,),
            (ArchiveInput(archive_ref, _coff_archive("pull.obj", _coff_object("_pull"))),),
        ),
        linker_inputs=("build/obj/unit.obj", archive_ref),
        products={
            node_id: CompilerProduct(
                node_id,
                "source/src/unit.cpp",
                "build/obj/unit.obj",
                effective_payload,
            )
        },
        counterfactual_objects={node_id: clean},
        effective_objects={node_id: effective},
        helper_sections={node_id: excluded},
        crt_pull_dependencies={node_id: dependencies},
        ordered_archive_seed_dependencies={},
    )

    pulls = trace["crt_pull_archive_provider_candidates"]
    assert isinstance(pulls, list)
    assert pulls[0]["name"] == "_pull"
    assert pulls[0]["ordinary_archive_definitions"] == ["system-library/runtime.lib(0:pull.obj)"]
    assert trace["crt_pull_extraction_closure"] == "terminal-literal-link-verification"


def test_helper_isolation_rejects_a_retained_local_relocation_into_helper_code() -> None:
    clean_payload = _coff_object("_entry")
    effective_payload = _coff_object_with_unreachable_helper_dependency(
        retained_helper_reference=True
    )
    clean = _parse_coff(clean_payload, "counterfactual.obj")
    effective = _parse_coff(effective_payload, "effective.obj")
    excluded, _definitions = _helper_delta_sections(
        clean=clean,
        effective=effective,
        helper_identifiers=("_helper",),
    )
    dependencies = _crt_pull_linker_dependencies(
        clean=clean,
        effective=effective,
        excluded_sections=excluded,
        helper_identifiers=("_helper",),
    )
    node_id = "compiler.app.0000"
    archive_ref = "system-library/runtime.lib"

    with pytest.raises(ClassicSemanticError, match="retained relocations into helper sections"):
        _helper_isolation_trace(
            target=TargetLinkClosure(
                "program",
                (node_id,),
                (archive_ref,),
                (
                    ArchiveInput(
                        archive_ref,
                        _coff_archive("pull.obj", _coff_object("_pull")),
                    ),
                ),
            ),
            linker_inputs=("build/obj/unit.obj", archive_ref),
            products={
                node_id: CompilerProduct(
                    node_id,
                    "source/src/unit.cpp",
                    "build/obj/unit.obj",
                    effective_payload,
                )
            },
            counterfactual_objects={node_id: clean},
            effective_objects={node_id: effective},
            helper_sections={node_id: excluded},
            crt_pull_dependencies={node_id: dependencies},
            ordered_archive_seed_dependencies={},
        )


@pytest.mark.parametrize("competitor", ("compiler", "import"))
def test_crt_pull_rejects_a_dependency_resolved_before_ordinary_archive_extraction(
    competitor: str,
) -> None:
    clean_payload = _coff_object("_entry")
    effective_payload = _coff_object_with_unreachable_helper_dependency()
    clean = _parse_coff(clean_payload, "counterfactual.obj")
    effective = _parse_coff(effective_payload, "effective.obj")
    excluded, _definitions = _helper_delta_sections(
        clean=clean,
        effective=effective,
        helper_identifiers=("_helper",),
    )
    dependencies = _crt_pull_linker_dependencies(
        clean=clean,
        effective=effective,
        excluded_sections=excluded,
        helper_identifiers=("_helper",),
    )
    helper_node = "compiler.app.0000"
    competitor_node = "compiler.app.0001"
    provider_ref = "system-library/runtime.lib"
    import_ref = "system-library/imports.lib"
    provider = ArchiveInput(
        provider_ref,
        _coff_archive("pull.obj", _coff_object("_pull")),
    )
    target_nodes = (helper_node, competitor_node) if competitor == "compiler" else (helper_node,)
    archive_refs = (provider_ref, import_ref) if competitor == "import" else (provider_ref,)
    archives = (
        (
            provider,
            ArchiveInput(
                import_ref,
                _coff_archive("pull.imp", _import_object("_pull", "runtime.dll")),
            ),
        )
        if competitor == "import"
        else (provider,)
    )
    products = {
        helper_node: CompilerProduct(
            helper_node,
            "source/src/unit.cpp",
            "build/obj/unit.obj",
            effective_payload,
        )
    }
    effective_objects = {helper_node: effective}
    if competitor == "compiler":
        competitor_payload = _coff_object("_pull")
        products[competitor_node] = CompilerProduct(
            competitor_node,
            "source/src/provider.cpp",
            "build/obj/provider.obj",
            competitor_payload,
        )
        effective_objects[competitor_node] = _parse_coff(competitor_payload, "provider.obj")

    with pytest.raises(ClassicSemanticError, match="resolves before ordinary archive extraction"):
        _helper_isolation_trace(
            target=TargetLinkClosure(
                "program",
                target_nodes,
                archive_refs,
                archives,
            ),
            linker_inputs=(
                "build/obj/unit.obj",
                *(("build/obj/provider.obj",) if competitor == "compiler" else ()),
                *archive_refs,
            ),
            products=products,
            counterfactual_objects={helper_node: clean},
            effective_objects=effective_objects,
            helper_sections={helper_node: excluded},
            crt_pull_dependencies={helper_node: dependencies},
            ordered_archive_seed_dependencies={},
        )


@pytest.mark.parametrize("import_only", (False, True))
def test_crt_pull_dependency_requires_an_ordinary_archive_definition(
    import_only: bool,
) -> None:
    clean_payload = _coff_object("_entry")
    effective_payload = _coff_object_with_unreachable_helper_dependency()
    clean = _parse_coff(clean_payload, "counterfactual.obj")
    effective = _parse_coff(effective_payload, "effective.obj")
    excluded, _definitions = _helper_delta_sections(
        clean=clean,
        effective=effective,
        helper_identifiers=("_helper",),
    )
    dependencies = _crt_pull_linker_dependencies(
        clean=clean,
        effective=effective,
        excluded_sections=excluded,
        helper_identifiers=("_helper",),
    )
    node_id = "compiler.app.0000"
    archive_ref = "system-library/runtime.lib"
    archives = (
        (
            ArchiveInput(
                archive_ref,
                _coff_archive("pull.obj", _import_object("_pull", "runtime.dll")),
            ),
        )
        if import_only
        else ()
    )
    archive_refs = (archive_ref,) if import_only else ()

    with pytest.raises(ClassicSemanticError, match=r"ordinary (?:declared )?archive"):
        _helper_isolation_trace(
            target=TargetLinkClosure(
                "program",
                (node_id,),
                archive_refs,
                archives,
            ),
            linker_inputs=("build/obj/unit.obj", *archive_refs),
            products={
                node_id: CompilerProduct(
                    node_id,
                    "source/src/unit.cpp",
                    "build/obj/unit.obj",
                    effective_payload,
                )
            },
            counterfactual_objects={node_id: clean},
            effective_objects={node_id: effective},
            helper_sections={node_id: excluded},
            crt_pull_dependencies={node_id: dependencies},
            ordered_archive_seed_dependencies={},
        )


def test_coff_envelope_accepts_an_exact_relocation_backed_text_tail() -> None:
    payload = _coff_object_with_relocated_text_tail()
    baseline = _parse_coff(payload, "baseline.obj")
    candidate = _parse_coff(payload, "candidate.obj")

    theorem = _coff_compiler_congruence_trace(
        baseline,
        candidate,
        excluded_effective_sections=frozenset(),
    )

    assert theorem["theorem"] == "closed-source-compiler-congruence-coff-envelope-v1"


def test_opaque_text_tail_alpha_normalizes_compiler_local_symbols() -> None:
    baseline_payload = _coff_object_with_relocated_text_tail()
    candidate_payload = baseline_payload
    for old, new in (("$L0", "$L9"), ("$L1", "$L8"), ("$L2", "$L7")):
        candidate_payload = _patch_coff_symbol_name(candidate_payload, old, new)

    theorem = _coff_compiler_congruence_trace(
        _parse_coff(baseline_payload, "baseline.obj"),
        _parse_coff(candidate_payload, "candidate.obj"),
        excluded_effective_sections=frozenset(),
    )

    assert theorem["theorem"] == "closed-source-compiler-congruence-coff-envelope-v1"


@pytest.mark.parametrize(
    "candidate_payload",
    (
        _coff_object_with_relocated_text_tail(prefix_byte=2),
        _coff_object_with_relocated_text_tail(first_slot_offset=25),
        _coff_object_with_relocated_text_tail(first_slot_type=7),
        _coff_object_with_relocated_text_tail(first_slot_addend=1),
        _coff_object_with_relocated_text_tail(first_slot_target="_ext1"),
        _coff_object_with_relocated_text_tail(first_target_value=13),
        _coff_object_with_relocated_text_tail(include_second_slot=False),
    ),
    ids=(
        "non-relocation-byte",
        "relocation-offset",
        "relocation-type",
        "relocation-addend",
        "relocation-target",
        "relocation-target-value",
        "relocation-count",
    ),
)
def test_opaque_text_tail_rejects_every_runtime_statement_change(
    candidate_payload: bytes,
) -> None:
    baseline = _parse_coff(
        _coff_object_with_relocated_text_tail(),
        "baseline.obj",
    )
    candidate = _parse_coff(candidate_payload, "candidate.obj")

    with pytest.raises(ClassicSemanticError, match="closed COFF semantic envelope"):
        _coff_compiler_congruence_trace(
            baseline,
            candidate,
            excluded_effective_sections=frozenset(),
        )


def test_opaque_text_tail_rejects_section_topology_change() -> None:
    payload = _coff_object_with_relocated_text_tail()
    changed = _patch_comdat_auxiliary(payload, selection=3)

    with pytest.raises(ClassicSemanticError, match="closed COFF semantic envelope"):
        _coff_compiler_congruence_trace(
            _parse_coff(payload, "baseline.obj"),
            _parse_coff(changed, "candidate.obj"),
            excluded_effective_sections=frozenset(),
        )


def test_opaque_and_instruction_code_modes_never_compare_equal() -> None:
    with pytest.raises(ClassicSemanticError, match="closed COFF semantic envelope"):
        _coff_compiler_congruence_trace(
            _parse_coff(
                _coff_object_with_relocated_text_tail(),
                "baseline.obj",
            ),
            _parse_coff(
                _coff_object("_entry", body_payload=b"\xc3"),
                "candidate.obj",
            ),
            excluded_effective_sections=frozenset(),
        )


def test_opaque_text_section_binds_relocation_record_order() -> None:
    baseline_payload = _coff_object_with_relocated_text_tail()
    candidate_payload = bytearray(baseline_payload)
    relocation_offset = struct.unpack_from("<I", candidate_payload, 20 + 24)[0]
    rows = [
        bytes(
            candidate_payload[relocation_offset + index * 10 : relocation_offset + (index + 1) * 10]
        )
        for index in range(3)
    ]
    candidate_payload[relocation_offset : relocation_offset + 30] = b"".join(
        (rows[0], rows[2], rows[1])
    )

    with pytest.raises(ClassicSemanticError, match="closed COFF semantic envelope"):
        _coff_compiler_congruence_trace(
            _parse_coff(baseline_payload, "baseline.obj"),
            _parse_coff(bytes(candidate_payload), "candidate.obj"),
            excluded_effective_sections=frozenset(),
        )


def test_undecodable_text_uses_only_the_opaque_exact_fallback() -> None:
    baseline = _parse_coff(
        _coff_object("_entry", body_payload=b"\xd6\xc3"),
        "baseline.obj",
    )
    changed = _parse_coff(
        _coff_object("_entry", body_payload=b"\xf1\xc3"),
        "changed.obj",
    )
    with pytest.raises(_SemanticCodePartitionError):
        _semantic_code_stream(baseline, baseline.sections[0])
    with pytest.raises(_SemanticCodePartitionError):
        _semantic_code_stream(changed, changed.sections[0])

    theorem = _coff_compiler_congruence_trace(
        baseline,
        baseline,
        excluded_effective_sections=frozenset(),
    )
    assert theorem["theorem"] == "closed-source-compiler-congruence-coff-envelope-v1"

    with pytest.raises(ClassicSemanticError, match="closed COFF semantic envelope"):
        _coff_compiler_congruence_trace(
            baseline,
            changed,
            excluded_effective_sections=frozenset(),
        )


def test_runtime_projection_accepts_compiler_local_symbol_alpha_only_delta() -> None:
    baseline = _append_coff_symbols(
        _coff_object("_entry"),
        _symbol("$L1", value=0, section=1, symbol_type=0, storage=3),
    )
    candidate = _append_coff_symbols(
        _coff_object("_entry"),
        _symbol("$L2", value=0, section=1, symbol_type=0, storage=3),
    )

    assert _runtime_projection_equivalence(
        _parse_coff(baseline, "baseline.obj"),
        _parse_coff(candidate, "candidate.obj"),
    ) == (
        True,
        False,
        "compiler-local-symbol-alpha-equivalence-v1",
    )


def test_runtime_projection_alpha_renames_a_defined_local_and_its_relocation() -> None:
    baseline = _coff_object_with_external_code_entry(b"\xc3", 0)
    candidate = bytearray(baseline)
    local_offset = _coff_symbol_offset(baseline, "$L1")
    candidate[local_offset : local_offset + 8] = b"$L2\0\0\0\0\0"

    assert _runtime_projection_equivalence(
        _parse_coff(baseline, "baseline.obj"),
        _parse_coff(bytes(candidate), "candidate.obj"),
    ) == (
        True,
        False,
        "compiler-local-symbol-alpha-equivalence-v1",
    )


def test_runtime_projection_alpha_rejects_relocation_to_a_different_local_seat() -> None:
    baseline = _append_coff_symbols(
        _coff_object_with_external_code_entry(b"\xc3", 0),
        _symbol("$L3", value=0, section=1, symbol_type=0, storage=3),
    )
    candidate = bytearray(baseline)
    for old, new in (("$L1", "$L2"), ("$L3", "$L4")):
        offset = _coff_symbol_offset(baseline, old)
        candidate[offset : offset + 8] = new.encode("ascii").ljust(8, b"\0")
    second_section = 20 + 40
    relocation_offset = struct.unpack_from("<I", candidate, second_section + 24)[0]
    # The appended local occupies raw symbol-table index six.  It has the
    # same section/value/type/storage as the original target, but is not the
    # paired symbol-record seat for the relocation.
    struct.pack_into("<I", candidate, relocation_offset + 4, 6)

    assert _runtime_projection_equivalence(
        _parse_coff(baseline, "baseline.obj"),
        _parse_coff(bytes(candidate), "candidate.obj"),
    ) == (False, False, None)


@pytest.mark.parametrize("owner", ("$L1", "$T1", "$done$1"))
def test_runtime_projection_does_not_alpha_normalize_an_external_definition(
    owner: str,
) -> None:
    alternate = owner[:-1] + "2"

    assert _runtime_projection_equivalence(
        _parse_coff(_coff_object(owner), "baseline.obj"),
        _parse_coff(_coff_object(alternate), "candidate.obj"),
    ) == (False, False, None)


@pytest.mark.parametrize("dependency", ("$L1", "$T1", "$done$1"))
def test_runtime_projection_does_not_alpha_normalize_an_undefined_external(
    dependency: str,
) -> None:
    alternate = dependency[:-1] + "2"

    assert _runtime_projection_equivalence(
        _parse_coff(
            _coff_object("_entry", reference=dependency),
            "baseline.obj",
        ),
        _parse_coff(
            _coff_object("_entry", reference=alternate),
            "candidate.obj",
        ),
    ) == (False, False, None)


def test_runtime_projection_accepts_only_independent_data_comdat_permutation() -> None:
    baseline = _parse_coff(
        _coff_object_with_permutable_data_comdats(("a", "b")),
        "baseline.obj",
    )
    candidate = _parse_coff(
        _coff_object_with_permutable_data_comdats(("b", "a")),
        "candidate.obj",
    )

    equivalence = _runtime_projection_equivalence_proof(baseline, candidate)

    assert equivalence.equivalent is True
    assert equivalence.byte_equal is False
    assert equivalence.theorem == "independent-relocation-free-data-comdat-permutation-v1"
    assert equivalence.proof is not None
    assert len(equivalence.proof["permutations"]) == 2
    trace = _coff_compiler_congruence_trace(
        baseline,
        candidate,
        excluded_effective_sections=frozenset(),
        projection_equivalence=equivalence,
    )
    assert "independent-relocation-free-data-comdat-order" in trace["allowed_deltas"]


@pytest.mark.parametrize(
    "options",
    (
        {"a_selection": 0},
        {"a_selection": 5, "a_associated": 1},
        {"a_relocation": True},
        {"a_section_name": ".CRT$XCU"},
    ),
)
def test_runtime_projection_rejects_order_sensitive_section_permutation(
    options: dict[str, object],
) -> None:
    baseline = _parse_coff(
        _coff_object_with_permutable_data_comdats(("a", "b"), **options),  # type: ignore[arg-type]
        "baseline.obj",
    )
    candidate = _parse_coff(
        _coff_object_with_permutable_data_comdats(("b", "a"), **options),  # type: ignore[arg-type]
        "candidate.obj",
    )

    assert _runtime_projection_equivalence(baseline, candidate) == (
        False,
        False,
        None,
    )


@pytest.mark.parametrize("mutation", ("body", "characteristics", "relocation", "comdat"))
def test_link_relevant_coff_projection_rejects_linker_visible_mutations(
    mutation: str,
) -> None:
    baseline_payload = _coff_object("_entry", reference="_dep")
    candidate_payload = bytearray(baseline_payload)
    if mutation == "body":
        candidate_payload[60] = 1
    elif mutation == "characteristics":
        characteristics = struct.unpack_from("<I", candidate_payload, 56)[0]
        struct.pack_into("<I", candidate_payload, 56, characteristics ^ 0x20)
    elif mutation == "relocation":
        symbol_offset = struct.unpack_from("<I", candidate_payload, 8)[0]
        candidate_payload[symbol_offset + 3 * 18 : symbol_offset + 3 * 18 + 8] = b"_alt\0\0\0\0"
    else:
        candidate_payload = bytearray(
            _patch_comdat_auxiliary(bytes(candidate_payload), selection=3)
        )

    baseline = classic_link_relevant_coff_projection(baseline_payload, label="baseline.obj")
    candidate = classic_link_relevant_coff_projection(
        bytes(candidate_payload), label=f"{mutation}.obj"
    )

    assert baseline.projection_digest != candidate.projection_digest
    assert baseline.statement != candidate.statement


def test_coff_line_number_correspondence_permits_only_ordinary_line_values() -> None:
    baseline_payload = _add_coff_line_table(
        _coff_object("_entry", reference="_dep"),
        ((0, 0), (0, 17)),
    )
    candidate_payload = _patch_coff_line_record(baseline_payload, 1, line=29)

    identity = prove_classic_coff_line_number_correspondence(
        baseline_payload,
        baseline_payload,
        baseline_label="baseline-a.obj",
        candidate_label="baseline-b.obj",
    )
    receipt = prove_classic_coff_line_number_correspondence(
        baseline_payload,
        candidate_payload,
        baseline_label="baseline.obj",
        candidate_label="candidate.obj",
    )

    assert identity.baseline_projection_digest == identity.candidate_projection_digest
    assert identity.line_number_deltas == ()
    assert receipt.baseline_object_digest != receipt.candidate_object_digest
    assert receipt.baseline_projection_digest != receipt.candidate_projection_digest
    assert len(receipt.line_number_deltas) == 1
    delta = receipt.line_number_deltas[0]
    assert (
        delta.section_index,
        delta.section_name,
        delta.record_index,
        delta.address,
        delta.baseline_line,
        delta.candidate_line,
    ) == (
        1,
        ".text",
        1,
        0,
        17,
        29,
    )
    assert receipt.statement_digest == Digest.from_bytes(canonical_json(receipt.statement))
    assert receipt.statement["allowed_delta"] == (
        "retained-section-ordinary-coff-line-number-value"
    )


@pytest.mark.parametrize(
    "mutation",
    (
        "line-address",
        "line-function-target",
        "line-row-count",
        "line-row-kind",
        "body",
        "characteristics",
        "relocation-target",
        "comdat-selection",
        "retained-symbol-value",
    ),
)
def test_coff_line_number_correspondence_rejects_every_non_line_value_mutation(
    mutation: str,
) -> None:
    baseline_payload = _add_coff_line_table(
        _coff_object("_entry", reference="_dep"),
        ((0, 0), (0, 17)),
    )
    if mutation == "line-address":
        candidate_payload = _patch_coff_line_record(baseline_payload, 1, value=1)
    elif mutation == "line-function-target":
        candidate_payload = _patch_coff_line_record(baseline_payload, 0, value=2)
    elif mutation == "line-row-count":
        candidate_payload = _add_coff_line_table(
            _coff_object("_entry", reference="_dep"),
            ((0, 0), (0, 17), (1, 18)),
        )
    elif mutation == "line-row-kind":
        candidate_payload = _patch_coff_line_record(baseline_payload, 1, line=0)
    elif mutation == "body":
        candidate = bytearray(baseline_payload)
        candidate[60] = 1
        candidate_payload = bytes(candidate)
    elif mutation == "characteristics":
        candidate = bytearray(baseline_payload)
        characteristics = struct.unpack_from("<I", candidate, 56)[0]
        struct.pack_into("<I", candidate, 56, characteristics ^ 0x20)
        candidate_payload = bytes(candidate)
    elif mutation == "relocation-target":
        candidate_payload = _patch_coff_symbol(baseline_payload, "_dep", section=1)
    elif mutation == "comdat-selection":
        candidate_payload = _patch_comdat_auxiliary(baseline_payload, selection=3)
    else:
        candidate_payload = _patch_coff_symbol(baseline_payload, "_entry", value=1)

    with pytest.raises(ClassicSemanticError, match="outside ordinary COFF line-number"):
        prove_classic_coff_line_number_correspondence(
            baseline_payload,
            candidate_payload,
            baseline_label="baseline.obj",
            candidate_label=f"{mutation}.obj",
        )


def test_coff_line_number_correspondence_rejects_a_linker_directive_change() -> None:
    baseline = _coff_object(
        "_dir",
        section_name=".drectve",
        body_payload=b"/include:_root ",
    )
    candidate = _coff_object(
        "_dir",
        section_name=".drectve",
        body_payload=b"/include:_next ",
    )

    with pytest.raises(ClassicSemanticError, match="outside ordinary COFF line-number"):
        prove_classic_coff_line_number_correspondence(
            baseline,
            candidate,
            baseline_label="baseline.obj",
            candidate_label="directive.obj",
        )


def test_archive_member_directive_parser_admits_the_strict_extension_shape() -> None:
    payload = bytearray(
        _coff_object("_dir", section_name=".drectve", body_payload=b"/include:_root ")
    )
    payload[:2] = b"\0\0"

    receipt = parse_classic_archive_member_directives(
        bytes(payload), label="library.lib(member.obj)"
    )

    assert receipt.include_symbols == ("_root",)
    with pytest.raises(ClassicSemanticError, match="import object"):
        parse_classic_archive_member_directives(
            _import_object("_puts", "runtime.dll"), label="library.lib(import.obj)"
        )


@pytest.mark.parametrize(
    ("section_name", "optional_size", "section_characteristics", "optional_version"),
    (
        (".debug$S", 0, 0x42100040, (3, 10, 4, 0)),
        (".idata$6", 0x00E0, 0xC0200040, (3, 10, 4, 0)),
        (".idata$6", 0x00E0, 0xC0200040, (5, 10, 4, 0)),
    ),
)
def test_project_overlay_archive_semantics_admits_classic_auxless_section_anchors(
    section_name: str,
    optional_size: int,
    section_characteristics: int,
    optional_version: tuple[int, int, int, int],
) -> None:
    member = _classic_archive_auxless_section_anchor(
        section_name,
        optional_size=optional_size,
        section_characteristics=section_characteristics,
        optional_version=optional_version,
    )
    archive_ref = "system-library/runtime.lib"
    target = TargetLinkClosure(
        "program",
        (),
        (archive_ref,),
        (ArchiveInput(archive_ref, _coff_archive("runtime.dll", member)),),
    )

    objects, imports, traces = _archive_semantics(
        target,
        compiler_digests=frozenset(),
        carrier_digests=frozenset(),
    )

    assert imports == []
    assert len(objects) == 1
    assert objects[0].coff.sections[0].comdat_selection is None
    assert traces[0]["ordinary_coff_members"] == 1
    with pytest.raises(ClassicSemanticError):
        _parse_coff(member, "direct-object.obj")


@pytest.mark.parametrize(
    ("machine", "extra_metadata", "message"),
    (
        (0, None, "definition symbol is non-canonical"),
        (0x014C, "auxless", "duplicate section-metadata symbols"),
        (0x014C, "canonical-after", "duplicate section-metadata symbols"),
    ),
)
def test_project_overlay_archive_semantics_rejects_inexact_section_metadata(
    machine: int,
    extra_metadata: str | None,
    message: str,
) -> None:
    member = _classic_archive_auxless_section_anchor(
        ".debug$S",
        optional_size=0,
        section_characteristics=0x42100040,
        machine=machine,
        extra_metadata=extra_metadata,
    )
    archive_ref = "system-library/runtime.lib"
    target = TargetLinkClosure(
        "program",
        (),
        (archive_ref,),
        (ArchiveInput(archive_ref, _coff_archive("runtime.dll", member)),),
    )

    with pytest.raises(ClassicSemanticError, match=message):
        _archive_semantics(
            target,
            compiler_digests=frozenset(),
            carrier_digests=frozenset(),
        )


def _base_authority(
    root: Path,
    *,
    generated_carrier: bool,
) -> tuple[
    ProjectBundle,
    ProducerGraphDocument,
    ClassicRecipeIntervention,
    ClassicRecipeIntervention | None,
    ClassicRecipeIntervention | None,
    bytes,
    bytes,
]:
    clean = b"int target() { return 1; }\n"
    effective = b"class EntropySeat {};\n" + clean
    carrier_path = "src/carrier.cpp"
    output_path = carrier_path if generated_carrier else "src/unit.cpp"
    output = {
        "path": output_path,
        "effective": Digest.from_bytes(effective).value,
        "size": len(effective),
        "ops": [{"op": "append", "gen": {"k": "lines", "n": 1}}],
    }
    if not generated_carrier:
        output["clean"] = Digest.from_bytes(clean).value
    overlay = ClassicRecipeIntervention(
        id="overlay.project",
        scope=Scope(target="program"),
        rationale="typed source entropy overlay",
        family=ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH,
        role=ClassicRecipeRole.PROJECT,
        build_target="app",
        parameters=(
            ClassicField(
                name="graph",
                value={
                    "generated_tus": ([{"path": carrier_path}] if generated_carrier else []),
                    "link_admissions": [],
                },
            ),
            ClassicField(name="outputs", value=[output]),
            ClassicField(name="schema", value=2),
        ),
    )
    donor: ClassicRecipeIntervention | None = None
    consumer: ClassicRecipeIntervention | None = None
    interventions: list[ClassicRecipeIntervention] = [overlay]
    if not generated_carrier:
        donor = ClassicRecipeIntervention(
            id="donor.shape",
            scope=Scope(target="program", translation_unit="tu.unit"),
            rationale="private donor compile",
            family=ClassicRecipeFamily.DECLARATION_SHAPE,
            role=ClassicRecipeRole.DONOR,
            build_target="app",
            beneficiaries=(
                Scope(
                    target="program",
                    translation_unit="tu.unit",
                    function="?target@@YAHXZ",
                ),
            ),
        )
        consumer = ClassicRecipeIntervention(
            id="function.target",
            scope=Scope(target="program", translation_unit="tu.unit", function="?target@@YAHXZ"),
            rationale="equal-body candidate transform",
            dependencies=(donor.id,),
            family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
            role=ClassicRecipeRole.FUNCTION,
            build_target="app",
            symbol="?target@@YAHXZ",
        )
        interventions.extend((donor, consumer))

    manifest = SourceManifestDocument(
        schema_version=3,
        complete=True,
        entries=(
            SourceManifestEntry(
                path="src/unit.cpp", size=len(clean), digest=Digest.from_bytes(clean)
            ),
        ),
    )
    toolchain = (
        ToolchainLock(
            schema_version=3,
            profile="msvc_4_2",
            release=MsvcRelease.V4_2,
            profile_sources=(
                ToolchainProfileSource(
                    repository="https://github.com/archaic-msvc/msvc420.git",
                    revision="b42c244f0a83ba15ba2ffb62b0dc240d7b2dea50",
                    paths=("bin/CL.EXE", "bin/LINK.EXE"),
                ),
            ),
            tools=(
                LockedTool(
                    id="compiler",
                    path="bin/CL.EXE",
                    digest=Digest.from_bytes(b"cl"),
                    size=2,
                    roles=("compiler",),
                ),
                LockedTool(
                    id="linker",
                    path="bin/LINK.EXE",
                    digest=Digest(
                        value=("6ca5a19155e4170e8df08247769b4586fa951743f09f1d8fcec838fc4eb9750e")
                    ),
                    size=514_048,
                    roles=("linker",),
                ),
            ),
        )
        if generated_carrier
        else ToolchainLock(
            schema_version=3,
            profile="msvc-42",
            release=MsvcRelease.V4_2,
            tools=(
                LockedTool(
                    id="compiler",
                    path="bin/cl.exe",
                    digest=Digest.from_bytes(b"cl"),
                    size=2,
                    roles=("compiler",),
                ),
            ),
        )
    )
    paths = LogicalPathProfile(source="Z:\\src", build="Z:\\build", toolchain="Z:\\toolchain")
    spec = ProjectSpec(
        schema_version=3,
        project_id="semantic-fixture",
        build=ProducerGraphBuildAdapter(),
        toolchain=ToolchainRef(profile=toolchain.profile),
        paths=paths,
        targets=(
            TargetSpec(id="program", artifact="out/program.exe", oracle="reference/program.exe"),
        ),
    )
    unit_plan = (
        ClassicTranslationUnitPlan(
            id="tu.unit",
            target_id="program",
            build_target="app",
            source="src/unit.cpp",
            source_digest=Digest.from_bytes(effective),
        )
        if donor is not None
        else None
    )
    intervention_documents = [
        InterventionDocument(
            schema_version=3,
            target_id="program",
            interventions=(overlay,),
        )
    ]
    proof_documents = [
        ProofDocument(
            schema_version=3,
            target_id="program",
            expected_observations=(
                ClassicProofReceipt(
                    id=f"proof.{overlay.id}",
                    intervention_id=overlay.id,
                    family=overlay.family,
                ),
            ),
        )
    ]
    if unit_plan is not None:
        unit_interventions = tuple(interventions[1:])
        intervention_documents.append(
            InterventionDocument(
                schema_version=3,
                target_id="program",
                translation_unit_id=unit_plan.id,
                source=unit_plan.source,
                source_digest=unit_plan.source_digest,
                build_target=unit_plan.build_target,
                interventions=unit_interventions,
            )
        )
        proof_documents.append(
            ProofDocument(
                schema_version=3,
                target_id="program",
                translation_unit_id=unit_plan.id,
                expected_observations=tuple(
                    ClassicProofReceipt(
                        id=f"proof.{item.id}",
                        intervention_id=item.id,
                        family=item.family,
                    )
                    for item in unit_interventions
                ),
            )
        )
    bundle = ProjectBundle(
        root=str(root),
        spec=spec,
        toolchain_lock=toolchain,
        source_manifest=manifest,
        build_plan=BuildPlanDocument(
            schema_version=3,
            source_manifest_digest=source_manifest_digest(manifest),
            translation_units=(unit_plan,) if unit_plan is not None else (),
            source_overlay_digest=Digest.from_bytes(
                canonical_json(overlay.model_dump(mode="json"))
            ),
            source_overlay_interventions=(overlay.id,),
            archives=(),
            target_gates=(
                ClassicTargetGate(
                    target_id="program",
                    build_target="app",
                ),
            ),
        ),
        intervention_documents=tuple(intervention_documents),
        proof_documents=tuple(proof_documents),
        oracle_documents=(
            OracleDocument(
                schema_version=3,
                target_id="program",
                image_size=1,
                image_digest=Digest.from_bytes(b"x"),
            ),
        ),
    )

    compiler_nodes = [
        ProducerNode(
            id="compiler.app.0000",
            role=ProducerRole.COMPILER,
            owner="app",
            arguments=("/c", "${SOURCE}/src/unit.cpp"),
            inputs=("source/src/unit.cpp",),
            outputs=("build/obj/unit.obj",),
        )
    ]
    if generated_carrier:
        compiler_nodes.append(
            ProducerNode(
                id="compiler.app.0001",
                role=ProducerRole.COMPILER,
                owner="app",
                arguments=("/c", "${SOURCE}/src/carrier.cpp"),
                inputs=("source/src/carrier.cpp",),
                outputs=("build/obj/carrier.obj",),
            )
        )
    object_inputs = tuple(
        sorted(
            (output for node in compiler_nodes for output in node.outputs),
            key=str.casefold,
        )
    )
    graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=source_topology_digest(item.path for item in manifest.entries),
        toolchain_lock_digest=toolchain_document_digest(toolchain),
        path_profile_id=paths.id,
        extractor="cmake-makefiles-v1",
        nodes=(
            *compiler_nodes,
            ProducerNode(
                id="linker.app.0002",
                role=ProducerRole.LINKER,
                owner="app",
                target_id="program",
                arguments=(
                    "/out:${BUILD}/out/program.exe",
                    "/incremental:no",
                    "/OPT:REF",
                    *("${BUILD}/" + item.removeprefix("build/") for item in object_inputs),
                ),
                inputs=object_inputs,
                outputs=("build/out/program.exe",),
                depends_on=tuple(node.id for node in compiler_nodes),
            ),
        ),
    )
    return bundle, graph, overlay, donor, consumer, clean, effective


def _donor_snapshot(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    donor: ClassicRecipeIntervention,
    consumer: ClassicRecipeIntervention,
    clean: bytes,
    effective: bytes,
) -> OverlaySemanticSnapshot:
    overlay_receipt = EffectiveOverlayReceipt(
        "src/unit.cpp", Digest.from_bytes(effective), len(effective)
    )
    seed_object = b"seed object"
    donor_object = b"donor object"
    candidate_object = b"candidate object"
    seed_digest = Digest.from_bytes(seed_object)
    donor_digest = Digest.from_bytes(donor_object)
    candidate_digest = Digest.from_bytes(candidate_object)
    statement = classic_candidate_input_statement(
        consumer,
        seed_input=seed_object,
        binary_inputs={f"dependency:{donor.id}": donor_object},
        source_inputs={},
        candidate_constraints={},
    )
    output_statement = {
        "schema": 1,
        "kind": "classic-closed-candidate-output",
        "candidate": {
            "digest": candidate_digest.model_dump(mode="json"),
            "size": len(candidate_object),
        },
        "validator_trace": {"same_linked_function_semantics": True},
    }
    semantic_proof = _issue_semantic_proof(
        family=consumer.family,
        contract=_BINARY_CONTRACT,
        input_statement=statement,
        output_statement=output_statement,
    )
    product = CompilerProduct(
        "compiler.app.0000",
        "source/src/unit.cpp",
        "build/obj/unit.obj",
        _coff_object("_main"),
    )
    return _bound_snapshot(
        graph,
        OverlaySemanticSnapshot(
            run_binding=Digest.from_bytes(b"run"),
            primary_sources=(
                SourceInputReceipt(
                    "src/unit.cpp",
                    Digest.from_bytes(clean),
                    len(clean),
                    PrimarySourceOrigin.CLEAN_MANIFEST,
                ),
            ),
            effective_outputs=(overlay_receipt,),
            compiler_products=(product,),
            donor_lanes=(
                DonorSemanticLane(
                    "program",
                    donor.id,
                    consumer.id,
                    (overlay_receipt,),
                    seed_digest,
                    donor_digest,
                    candidate_digest,
                    statement,
                    output_statement,
                    semantic_proof,
                    f"dependency:{donor.id}",
                ),
            ),
            link_closures=(
                TargetLinkClosure(
                    "program",
                    ("compiler.app.0000",),
                    demand_root_symbols=("_main",),
                ),
            ),
        ),
    )


def _seat_digest(tokens: list[str]) -> str:
    return Digest.from_bytes("\0".join(tokens).encode("ascii")).value


def _function_scope_claim(
    source: bytes,
    *,
    function: str,
    operation: str,
    bindings: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    short_name = function.rsplit("::", 1)[-1].encode("ascii")
    name_at = source.index(short_name)
    start = source.index(b"{", name_at)
    depth = 0
    end = -1
    for offset in range(start, len(source)):
        if source[offset : offset + 1] == b"{":
            depth += 1
        elif source[offset : offset + 1] == b"}":
            depth -= 1
            if depth == 0:
                end = offset + 1
                break
    assert end > start
    body = source[start:end]
    return {
        "kind": "function_scope",
        "operation": operation,
        "leaf": 0,
        "function": function,
        "range_sha256": Digest.from_bytes(body).value,
        "range_size": len(body),
        "bindings": bindings or [],
    }


def _certified_project_overlay_authority(
    tmp_path: Path,
    *,
    clean: bytes = b"int value;\n",
    effective: bytes | None = None,
    operations: list[dict[str, object]] | None = None,
    semantic_claims: dict[str, object] | None = None,
    clean_object_payload: bytes | None = None,
    effective_object_payload: bytes | None = None,
) -> tuple[
    ProjectBundle,
    ProducerGraphDocument,
    ClassicRecipeIntervention,
    OverlaySemanticSnapshot,
]:
    bundle, graph, original, _donor, _consumer, _old_clean, _old_effective = _base_authority(
        tmp_path, generated_carrier=False
    )
    if effective is None:
        effective = b"class Spare;\n" + clean
    if operations is None:
        operations = [
            {
                "op": "insert",
                "anchor": {
                    "ctx": _seat_digest(["<SEAT>", "int", "value", ";"]),
                    "b": 0,
                    "a": 3,
                    "at": "start",
                },
                "gen": {"k": "fwd", "id": "Spare"},
            }
        ]
    output = {
        "path": "src/unit.cpp",
        "clean": Digest.from_bytes(clean).value,
        "effective": Digest.from_bytes(effective).value,
        "size": len(effective),
        "ops": operations,
    }
    values = {item.name: item.value for item in original.parameters}
    values["outputs"] = [output]
    values["semantic_claims"] = semantic_claims or {"schema": 1, "bindings": []}
    overlay = original.model_copy(
        update={
            "parameters": tuple(
                ClassicField(name=name, value=value) for name, value in sorted(values.items())
            )
        }
    )
    manifest = SourceManifestDocument(
        schema_version=3,
        complete=True,
        entries=(
            SourceManifestEntry(
                path="src/unit.cpp", size=len(clean), digest=Digest.from_bytes(clean)
            ),
        ),
    )
    intervention_document = bundle.intervention_documents[0].model_copy(
        update={"interventions": (overlay,)}
    )
    source_digest = Digest.from_bytes(effective)
    remaining_documents = tuple(
        document.model_copy(update={"source_digest": source_digest})
        if document.translation_unit_id is not None
        else document
        for document in bundle.intervention_documents[1:]
    )
    assert bundle.build_plan is not None
    translation_units = tuple(
        unit.model_copy(update={"source_digest": source_digest})
        for unit in bundle.build_plan.translation_units
    )
    bundle = bundle.model_copy(
        update={
            "source_manifest": manifest,
            "build_plan": bundle.build_plan.model_copy(
                update={
                    "source_manifest_digest": source_manifest_digest(manifest),
                    "translation_units": translation_units,
                }
            ),
            "intervention_documents": (
                intervention_document,
                *remaining_documents,
            ),
        }
    )
    graph = graph.model_copy(
        update={
            "source_topology_digest": source_topology_digest(item.path for item in manifest.entries)
        }
    )
    clean_object = clean_object_payload or _coff_object("_main")
    effective_object = effective_object_payload or clean_object
    compiler_node = next(node for node in graph.nodes if node.role is ProducerRole.COMPILER)
    source_pair = ProjectOverlaySourcePair("src/unit.cpp", clean, effective)
    clean_input = CleanSourceInput("src/unit.cpp", clean)
    try:
        epoch_plan = plan_project_overlay_compiler_epochs(
            bundle,
            graph,
            (source_pair,),
            (clean_input,),
        )
    except ClassicSemanticError:
        # Negative fixtures deliberately construct malformed semantic
        # authorities.  Keep fixture assembly independent from the public
        # proof boundary so the assertion observes the intended rejection.
        epoch_plan = ProjectOverlayCompilerEpochPlan(
            {"src/unit.cpp": effective},
            frozenset(),
            frozenset(),
            {"src/unit.cpp": ()},
        )
    counterfactual = epoch_plan.declaration_outputs["src/unit.cpp"]
    counterfactual_invocation, counterfactual_namespace = _compiler_invocation(
        bundle,
        graph,
        compiler_node,
        (
            CompilerSourceRead(
                "source/src/unit.cpp",
                Digest.from_bytes(counterfactual),
                len(counterfactual),
                None,
                counterfactual,
            ),
        ),
        namespace_id="counterfactual",
    )
    effective_invocation, effective_namespace = _compiler_invocation(
        bundle,
        graph,
        compiler_node,
        (
            CompilerSourceRead(
                "source/src/unit.cpp",
                Digest.from_bytes(effective),
                len(effective),
                None,
                effective,
            ),
        ),
        namespace_id="effective",
    )
    counterfactual_audits = (
        (
            ProjectOverlayCounterfactualAudit(
                "compiler.app.0000",
                "source/src/unit.cpp",
                "build/obj/unit.obj",
                clean_object,
                counterfactual_invocation,
            ),
        )
        if epoch_plan.audit_node_ids
        else ()
    )
    snapshot = OverlaySemanticSnapshot(
        run_binding=Digest.from_bytes(b"certified project overlay run"),
        primary_sources=(
            SourceInputReceipt(
                "src/unit.cpp",
                Digest.from_bytes(effective),
                len(effective),
                PrimarySourceOrigin.CERTIFIED_PROJECT_OVERLAY,
            ),
        ),
        effective_outputs=(
            EffectiveOverlayReceipt("src/unit.cpp", Digest.from_bytes(effective), len(effective)),
        ),
        compiler_products=(
            CompilerProduct(
                "compiler.app.0000",
                "source/src/unit.cpp",
                "build/obj/unit.obj",
                effective_object,
                (),
                effective_invocation,
            ),
        ),
        donor_lanes=(),
        link_closures=(
            TargetLinkClosure(
                "program",
                ("compiler.app.0000",),
                demand_root_symbols=("_main",),
            ),
        ),
        project_source_pairs=(source_pair,),
        counterfactual_compiler_audits=counterfactual_audits,
        counterfactual_namespace_id=(
            counterfactual_namespace.namespace_id
            if epoch_plan.audit_node_ids
            else effective_namespace.namespace_id
        ),
        clean_source_inputs=(clean_input,),
        compiler_namespaces=(
            (counterfactual_namespace, effective_namespace)
            if epoch_plan.audit_node_ids
            else (effective_namespace,)
        ),
    )
    return bundle, graph, overlay, _bound_snapshot(graph, snapshot)


def test_record_header_owns_its_canonical_guard_definition(tmp_path: Path) -> None:
    clean = b"int value;\n"
    fragment = (
        b"#ifndef FRESH_GUARD\n#define FRESH_GUARD\nenum FreshRecord {\n\tFreshValue\n};\n#endif\n"
    )
    operation = {
        "op": "insert",
        "anchor": {
            "ctx": _seat_digest(["<SEAT>", "int", "value", ";"]),
            "b": 0,
            "a": 3,
            "at": "start",
        },
        "gen": {
            "k": "record_header",
            "logical_path": "src/unit.cpp",
            "typed_recipe": {
                "kind": "enum_one_enumerator",
                "guard": "FRESH_GUARD",
                "items": [{"name": "FreshRecord", "enumerator": "FreshValue"}],
            },
        },
    }
    bundle, graph, overlay, snapshot = _certified_project_overlay_authority(
        tmp_path,
        clean=clean,
        effective=fragment + clean,
        operations=[operation],
    )

    result = prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})

    assert result.proofs[overlay.id].family == ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH


def test_overlay_semantics_ignore_non_code_source_authority(tmp_path: Path) -> None:
    bundle, graph, _overlay, snapshot = _certified_project_overlay_authority(tmp_path)
    assert bundle.source_manifest is not None
    assert bundle.build_plan is not None
    readme = b"Project notes mention the generated name Spare, but are not compiler input.\n"
    manifest = bundle.source_manifest.model_copy(
        update={
            "entries": (
                *bundle.source_manifest.entries,
                SourceManifestEntry(
                    path="README.md",
                    size=len(readme),
                    digest=Digest.from_bytes(readme),
                ),
            )
        }
    )
    bundle = bundle.model_copy(
        update={
            "source_manifest": manifest,
            "build_plan": bundle.build_plan.model_copy(
                update={"source_manifest_digest": source_manifest_digest(manifest)}
            ),
        }
    )
    graph = graph.model_copy(
        update={
            "source_topology_digest": source_topology_digest(item.path for item in manifest.entries)
        }
    )

    plan = plan_project_overlay_compiler_epochs(
        bundle,
        graph,
        snapshot.project_source_pairs,
        (*snapshot.clean_source_inputs, CleanSourceInput("README.md", readme)),
    )

    assert plan.declaration_outputs["src/unit.cpp"].startswith(b"class Spare;")

    snapshot = replace(
        snapshot,
        primary_sources=(
            *snapshot.primary_sources,
            SourceInputReceipt(
                "README.md",
                Digest.from_bytes(readme),
                len(readme),
                PrimarySourceOrigin.CLEAN_MANIFEST,
            ),
        ),
        clean_source_inputs=(
            *snapshot.clean_source_inputs,
            CleanSourceInput("README.md", readme),
        ),
    )
    readme_read = CompilerSourceRead(
        "source/README.md",
        Digest.from_bytes(readme),
        len(readme),
        None,
        readme,
    )
    namespaces: list[CompilerNamespaceEvidence] = []
    for namespace in snapshot.compiler_namespaces:
        updated_namespace = replace(
            namespace,
            members=tuple(
                sorted(
                    (*namespace.members, readme_read),
                    key=lambda item: item.reference.casefold(),
                )
            ),
        )
        namespaces.append(
            replace(
                updated_namespace,
                namespace_digest=compiler_namespace_evidence_digest(updated_namespace),
            )
        )
    namespace_by_id = {item.namespace_id: item for item in namespaces}

    def update_invocation(value: CompilerEpochInvocation) -> CompilerEpochInvocation:
        namespace = namespace_by_id[value.namespace_id]
        updated = replace(
            value,
            namespace_digest=namespace.namespace_digest,
            namespace_count=len(namespace.members),
        )
        return replace(updated, invocation_digest=compiler_epoch_invocation_digest(updated))

    snapshot = replace(
        snapshot,
        compiler_namespaces=tuple(namespaces),
        compiler_products=tuple(
            replace(
                product,
                compiler_invocation=update_invocation(product.compiler_invocation),
            )
            for product in snapshot.compiler_products
            if isinstance(product.compiler_invocation, CompilerEpochInvocation)
        ),
        counterfactual_compiler_audits=tuple(
            replace(
                audit,
                counterfactual_invocation=update_invocation(audit.counterfactual_invocation),
            )
            for audit in snapshot.counterfactual_compiler_audits
            if isinstance(audit.counterfactual_invocation, CompilerEpochInvocation)
        ),
    )
    result = prove_source_overlay_semantics(
        bundle,
        graph,
        _bound_snapshot(graph, snapshot),
        semantic_contracts={},
    )

    assert result.trace


@pytest.mark.parametrize(
    ("guard", "typed_recipe", "fragment"),
    (
        (
            "FreshRecord",
            {
                "kind": "enum_one_enumerator",
                "guard": "FreshRecord",
                "items": [{"name": "FreshRecord", "enumerator": "FreshValue"}],
            },
            (
                b"#ifndef FreshRecord\n#define FreshRecord\n"
                b"enum FreshRecord {\n\tFreshValue\n};\n#endif\n"
            ),
        ),
        (
            "Record0",
            {
                "kind": "unused_class_with_inline_void_methods",
                "guard": "Record0",
                "items": ["FreshRecord"],
                "method_identifier_policy": "zero_based_indexed_record",
                "methods_per_class": 1,
            },
            (
                b"#ifndef Record0\n#define Record0\n"
                b"class FreshRecord {\n\tinline void Record0() {}\n};\n#endif\n"
            ),
        ),
    ),
)
def test_record_header_guard_cannot_capture_its_guarded_body(
    tmp_path: Path,
    guard: str,
    typed_recipe: dict[str, object],
    fragment: bytes,
) -> None:
    clean = b"int value;\n"
    operation = {
        "op": "insert",
        "anchor": {
            "ctx": _seat_digest(["<SEAT>", "int", "value", ";"]),
            "b": 0,
            "a": 3,
            "at": "start",
        },
        "gen": {
            "k": "record_header",
            "logical_path": "src/unit.cpp",
            "typed_recipe": typed_recipe,
        },
    }
    bundle, graph, _overlay, snapshot = _certified_project_overlay_authority(
        tmp_path,
        clean=clean,
        effective=fragment + clean,
        operations=[operation],
    )

    with pytest.raises(ClassicSemanticError, match=rf"guard is not globally fresh: '{guard}'"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def _function_overlay_authority(
    tmp_path: Path,
    *,
    clean: bytes,
    seat: int,
    before_tokens: list[str],
    after_tokens: list[str],
    generator: dict[str, object],
    fragment: bytes,
    bindings: list[dict[str, object]] | None = None,
    clean_object: bytes | None = None,
    effective_object: bytes | None = None,
) -> tuple[
    ProjectBundle,
    ProducerGraphDocument,
    ClassicRecipeIntervention,
    OverlaySemanticSnapshot,
]:
    effective = clean[:seat] + fragment + clean[seat:]
    operation_id = "op_function"
    operation = {
        "id": operation_id,
        "op": "insert",
        "anchor": {
            "ctx": _seat_digest([*before_tokens, "<SEAT>", *after_tokens]),
            "b": len(before_tokens),
            "a": len(after_tokens),
            "at": "before_token",
        },
        "gen": generator,
    }
    return _certified_project_overlay_authority(
        tmp_path,
        clean=clean,
        effective=effective,
        operations=[operation],
        semantic_claims={
            "schema": 1,
            "bindings": [
                _function_scope_claim(
                    clean,
                    function="main",
                    operation=operation_id,
                    bindings=bindings,
                )
            ],
        },
        clean_object_payload=clean_object,
        effective_object_payload=effective_object,
    )


def _empty_scope_overlay_authority(
    tmp_path: Path,
    *,
    clean: bytes,
    seat: int,
    before_tokens: list[str],
    after_tokens: list[str],
    clean_object: bytes | None = None,
    effective_object: bytes | None = None,
) -> tuple[
    ProjectBundle,
    ProducerGraphDocument,
    ClassicRecipeIntervention,
    OverlaySemanticSnapshot,
]:
    return _function_overlay_authority(
        tmp_path,
        clean=clean,
        seat=seat,
        before_tokens=before_tokens,
        after_tokens=after_tokens,
        generator={"k": "empty_scopes", "scope_count": 1},
        fragment=b"\t{\n\t}\n",
        clean_object=clean_object,
        effective_object=effective_object,
    )


def _strict_project_overlay_authority(
    tmp_path: Path,
    *,
    counterfactual_object: bytes | None = None,
    effective_object: bytes | None = None,
) -> tuple[
    ProjectBundle,
    ProducerGraphDocument,
    ClassicRecipeIntervention,
    OverlaySemanticSnapshot,
]:
    clean = b"int main() {\n\treturn 0;\n}\n"
    return _empty_scope_overlay_authority(
        tmp_path,
        clean=clean,
        seat=clean.index(b"return"),
        before_tokens=["{"],
        after_tokens=["return", "0", ";"],
        clean_object=counterfactual_object,
        effective_object=effective_object,
    )


def _typedef_overlay_authority(
    tmp_path: Path,
    *,
    aliased_type: str = "int",
    used_by_generated_member: bool = False,
    clean_object: bytes | None = None,
    effective_object: bytes | None = None,
) -> tuple[
    ProjectBundle,
    ProducerGraphDocument,
    ClassicRecipeIntervention,
    OverlaySemanticSnapshot,
]:
    clean = b"int value;\n"
    items: list[dict[str, object]] = [
        {
            "k": "typedef",
            "id": "FreshAlias",
            "aliased_type": aliased_type,
            "line": 1,
        }
    ]
    lines = 1
    fragment = f"\ttypedef {aliased_type} FreshAlias;\n".encode("ascii")
    if used_by_generated_member:
        items.append(
            {
                "k": "class",
                "id": "FreshOwner",
                "members": ["FreshAlias"],
                "line": 2,
            }
        )
        lines = 4
        fragment += b"class FreshOwner {\n\tvoid FreshAlias() {}\n};\n"
    operation = {
        "op": "insert",
        "anchor": {
            "ctx": _seat_digest(["<SEAT>", "int", "value", ";"]),
            "b": 0,
            "a": 3,
            "at": "start",
        },
        "gen": {"k": "seq", "items": items, "lines": lines},
    }
    return _certified_project_overlay_authority(
        tmp_path,
        clean=clean,
        effective=fragment + clean,
        operations=[operation],
        clean_object_payload=clean_object,
        effective_object_payload=effective_object,
    )


def _typedef_seat_overlay_authority(
    tmp_path: Path,
    *,
    clean: bytes,
    seat: int,
    before_tokens: list[str],
    after_tokens: list[str],
    identifier: str = "FreshAlias",
) -> tuple[
    ProjectBundle,
    ProducerGraphDocument,
    ClassicRecipeIntervention,
    OverlaySemanticSnapshot,
]:
    while clean[seat : seat + 1] in {b" ", b"\t"}:
        seat += 1
    fragment = f"\ttypedef int {identifier};\n".encode("ascii")
    operation = {
        "id": "op_typedef",
        "op": "insert",
        "anchor": {
            "ctx": _seat_digest([*before_tokens, "<SEAT>", *after_tokens]),
            "b": len(before_tokens),
            "a": len(after_tokens),
            "at": "before_token",
        },
        "gen": {
            "k": "typedef",
            "id": identifier,
            "aliased_type": "int",
        },
    }
    return _certified_project_overlay_authority(
        tmp_path,
        clean=clean,
        effective=clean[:seat] + fragment + clean[seat:],
        operations=[operation],
    )


def _global_declaration_line_seat_authority(
    tmp_path: Path,
    *,
    clean: bytes,
    seat_marker: bytes,
    counterfactual_object: bytes | None = None,
    effective_object: bytes | None = None,
) -> tuple[
    ProjectBundle,
    ProducerGraphDocument,
    ClassicRecipeIntervention,
    OverlaySemanticSnapshot,
]:
    seat = clean.index(seat_marker)
    while clean[seat : seat + 1] in {b" ", b"\t"}:
        seat += 1
    token_records = tuple(source_overlay_tokens(clean))
    before_tokens = [token for token, _start, end in token_records if end <= seat]
    after_tokens = [token for token, start, _end in token_records if start >= seat]
    fragment = b"class Spare;\n"
    operation = {
        "id": "op_declaration_line",
        "op": "insert",
        "anchor": {
            "ctx": _seat_digest([*before_tokens, "<SEAT>", *after_tokens]),
            "b": len(before_tokens),
            "a": len(after_tokens),
            "at": "before_token",
        },
        "gen": {"k": "fwd", "id": "Spare"},
    }
    return _certified_project_overlay_authority(
        tmp_path,
        clean=clean,
        effective=clean[:seat] + fragment + clean[seat:],
        operations=[operation],
        clean_object_payload=counterfactual_object,
        effective_object_payload=effective_object,
    )


def test_global_declaration_odr_accepts_redundant_forward_and_identical_definitions() -> None:
    definition = _declaration_fact(source="src/one.cpp")
    repeated = _declaration_fact(source="src/two.cpp")
    forward = _declaration_fact(
        disposition="record-forward",
        signature=b"class FreshRecord;",
        source="src/three.cpp",
    )

    trace = _validate_declaration_odr({"FreshRecord": (definition, repeated, forward)})

    assert trace["repeated_identifier_count"] == 1
    assert trace["theorem"] == "target-closed-global-declaration-odr-v1"


@pytest.mark.parametrize(
    ("clean", "predecessor", "projection_required"),
    (
        (
            b"CHECK_SIZE(Type)\n// generated owner follows\nint value;\n",
            "function-like-macro-invocation",
            True,
        ),
        (
            b'#include "types.h"\n// generated owner follows\nint value;\n',
            "preprocessor-directive",
            False,
        ),
    ),
)
def test_global_declaration_line_fallback_binds_its_required_evidence(
    tmp_path: Path,
    clean: bytes,
    predecessor: str,
    projection_required: bool,
) -> None:
    bundle, graph, overlay, snapshot = _global_declaration_line_seat_authority(
        tmp_path,
        clean=clean,
        seat_marker=b"int value",
    )

    result = prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})

    epoch = result.trace[overlay.id]["project_overlay_epoch"]  # type: ignore[index]
    audits = epoch["compiler_audits"]  # type: ignore[index]
    if projection_required:
        assert len(audits) == 1
        assert audits[0]["runtime_projection_required"] is True
        assert audits[0]["runtime_projection_equal"] is True
    else:
        assert audits == []
    assert epoch["source_validation"]["extended_global_declaration_line_seats"] == [  # type: ignore[index]
        {
            "theorem": (
                "compiler-projected-global-declaration-line-seat-v1"
                if projection_required
                else "comment-separated-preprocessor-declaration-line-seat-v1"
            ),
            "source_path": "src/unit.cpp",
            "operation": "op_declaration_line",
            "generator": "fwd",
            "predecessor": predecessor,
            "runtime_projection_required": projection_required,
        }
    ]


def test_global_declaration_line_fallback_rejects_runtime_projection_change(
    tmp_path: Path,
) -> None:
    bundle, graph, _overlay, snapshot = _global_declaration_line_seat_authority(
        tmp_path,
        clean=b"CHECK_SIZE(Type)\nint value;\n",
        seat_marker=b"int value",
        effective_object=_coff_object("_main", body_payload=b"\xb8\x01\0\0\0\xc3"),
    )

    with pytest.raises(
        ClassicSemanticError,
        match=r"MSVC 4\.20 compiler-state code pair '_main' changes section topology",
    ):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_global_declaration_line_fallback_accepts_closed_cmp_reversal_theorem(
    tmp_path: Path,
) -> None:
    counterfactual = _coff_object(
        "_main",
        body_payload=b"\x3b\xc1\x74\x03\x83\xc0\x00\x83\xc1\x00\xc3",
    )
    effective = _coff_object(
        "_main",
        body_payload=b"\x3b\xc8\x74\x03\x83\xc0\x00\x83\xc1\x00\xc3",
    )
    bundle, graph, overlay, snapshot = _global_declaration_line_seat_authority(
        tmp_path,
        clean=b"CHECK_SIZE(Type)\nint value;\n",
        seat_marker=b"int value",
        counterfactual_object=counterfactual,
        effective_object=effective,
    )

    result = prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})

    epoch = result.trace[overlay.id]["project_overlay_epoch"]  # type: ignore[index]
    audits = epoch["compiler_audits"]  # type: ignore[index]
    assert audits[0]["runtime_projection_equal"] is False
    assert audits[0]["runtime_projection_equivalent"] is True
    assert audits[0]["runtime_projection_byte_equal"] is False
    assert (
        audits[0]["runtime_projection_theorem"]
        == "ia32-equality-compare-operand-reversal-flags-dead-v1"
    )


@pytest.mark.parametrize(
    ("clean", "seat_marker"),
    (
        (b"CHECK_SIZE(Type)\\\nint value;\n", b"int value"),
        (b"CHECK_SIZE(Type) C(Other)\nint value;\n", b"int value"),
        (b"CHECK_SIZE(Type) + C(Other)\nint value;\n", b"int value"),
        (b"extern\nint value;\n", b"int value"),
        (b'#include "types.h"??/\nint value;\n', b"int value"),
        (b'#include "types.h"\n// continued\\\nint value;\n', b"int value"),
        (
            b'#include "types.h"\n/* continued\\\ncomment */\nint value;\n',
            b"int value",
        ),
        (b"int main() {\nlabel:\n\treturn 0;\n}\n", b"\treturn"),
    ),
)
def test_global_declaration_line_fallback_rejects_splices_partial_declarations_and_labels(
    tmp_path: Path,
    clean: bytes,
    seat_marker: bytes,
) -> None:
    bundle, graph, _overlay, snapshot = _global_declaration_line_seat_authority(
        tmp_path,
        clean=clean,
        seat_marker=seat_marker,
    )

    with pytest.raises(ClassicSemanticError, match="closed declaration boundary"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_global_declaration_odr_allows_divergent_private_target_universes() -> None:
    first = _declaration_fact(
        signature=b"class FreshRecord { void first(); };",
        source="src/first.cpp",
        targets=("first",),
    )
    second = _declaration_fact(
        signature=b"class FreshRecord { void second(); };",
        source="src/second.cpp",
        targets=("second",),
    )

    _validate_declaration_odr({"FreshRecord": (first, second)})


@pytest.mark.parametrize(
    ("left", "right"),
    (
        (
            _declaration_fact(
                signature=b"class FreshRecord { void first(); };",
                source="src/first.cpp",
            ),
            _declaration_fact(
                signature=b"class FreshRecord { void second(); };",
                source="src/second.cpp",
            ),
        ),
        (
            _declaration_fact(source="src/repeated.cpp"),
            _declaration_fact(source="src/repeated.cpp"),
        ),
        (
            _declaration_fact(
                disposition="record-forward",
                signature=b"struct FreshRecord;",
                source="src/first.cpp",
                tag="struct",
            ),
            _declaration_fact(source="src/second.cpp", tag="class"),
        ),
        (
            _declaration_fact(
                identifier="FreshEnumerator",
                primary="FirstEnum",
                disposition="enumerator-definition",
                signature=b"enum FirstEnum { FreshEnumerator };",
                source="src/first.cpp",
                tag=None,
            ),
            _declaration_fact(
                identifier="FreshEnumerator",
                primary="SecondEnum",
                disposition="enumerator-definition",
                signature=b"enum SecondEnum { FreshEnumerator };",
                source="src/second.cpp",
                tag=None,
            ),
        ),
    ),
)
def test_global_declaration_odr_rejects_incompatible_repeated_entities(
    left: _DeclarationFact,
    right: _DeclarationFact,
) -> None:
    with pytest.raises(ClassicSemanticError, match="ODR compatibility"):
        _validate_declaration_odr({left.identifier: (left, right)})


def test_strict_project_overlay_requires_and_binds_both_compiler_epochs(
    tmp_path: Path,
) -> None:
    clean = b"int main() {\n\treturn 0;\n}\n"
    bundle, graph, overlay, snapshot = _empty_scope_overlay_authority(
        tmp_path,
        clean=clean,
        seat=clean.index(b"return"),
        before_tokens=["{"],
        after_tokens=["return", "0", ";"],
    )

    result = prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})

    trace = result.trace[overlay.id]
    assert trace["project_overlay_epoch"]["enabled"] is True  # type: ignore[index]
    source_validation = trace["project_overlay_epoch"]["source_validation"]  # type: ignore[index]
    assert source_validation["declaration_counterfactual"]["selected_leaf_keys"] == [
        {"operation_id": "op_function", "leaf_index": 0}
    ]
    namespaces = trace["project_overlay_epoch"]["compiler_namespaces"]  # type: ignore[index]
    assert [item["namespace_id"] for item in namespaces] == [
        "counterfactual",
        "effective",
    ]
    assert all("members" not in item for item in namespaces)
    audit = trace["project_overlay_epoch"]["compiler_audits"][0]  # type: ignore[index]
    assert audit["counterfactual_digest"] == audit["effective_digest"]
    congruence = audit["compiler_congruence"]
    assert "reads" not in congruence
    assert congruence["counterfactual_namespace"]["id"] == "counterfactual"
    assert congruence["effective_namespace"]["id"] == "effective"
    proof = result.proofs[overlay.id]
    assert proof.input_statement is not None
    assert proof.output_statement == trace
    assert proof.output_statement_digest == Digest.from_bytes(canonical_json(trace))


def test_declaration_only_epoch_plan_needs_no_counterfactual_compile(tmp_path: Path) -> None:
    bundle, graph, _overlay, snapshot = _certified_project_overlay_authority(tmp_path)

    plan = plan_project_overlay_compiler_epochs(
        bundle,
        graph,
        snapshot.project_source_pairs,
        snapshot.clean_source_inputs,
    )

    assert plan.audit_node_ids == frozenset()
    assert plan.runtime_projection_node_ids == frozenset()
    assert plan.declaration_outputs == {"src/unit.cpp": b"class Spare;\nint value;\n"}


def _with_secondary_compiler_reader(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    snapshot: OverlaySemanticSnapshot,
    *,
    payload: bytes,
    leading_arguments: tuple[str, ...] = (),
) -> tuple[
    ProjectBundle,
    ProducerGraphDocument,
    tuple[ProjectOverlaySourcePair, ...],
    tuple[CleanSourceInput, ...],
]:
    reader_path = "src/reader.cpp"
    assert bundle.source_manifest is not None
    manifest = SourceManifestDocument(
        schema_version=3,
        complete=True,
        entries=tuple(
            sorted(
                (
                    *bundle.source_manifest.entries,
                    SourceManifestEntry(
                        path=reader_path,
                        size=len(payload),
                        digest=Digest.from_bytes(payload),
                    ),
                ),
                key=lambda item: item.path.casefold(),
            )
        ),
    )
    assert bundle.build_plan is not None
    bundle = bundle.model_copy(
        update={
            "source_manifest": manifest,
            "build_plan": bundle.build_plan.model_copy(
                update={"source_manifest_digest": source_manifest_digest(manifest)}
            ),
        }
    )

    compiler = next(node for node in graph.nodes if node.role is ProducerRole.COMPILER)
    old_linker = next(node for node in graph.nodes if node.role is ProducerRole.LINKER)
    reader = ProducerNode(
        id="compiler.app.0001",
        role=ProducerRole.COMPILER,
        owner="app",
        arguments=(*leading_arguments, "/c", "${SOURCE}/src/reader.cpp"),
        inputs=("source/src/reader.cpp",),
        outputs=("build/obj/reader.obj",),
    )
    linker = ProducerNode(
        id=old_linker.id,
        role=old_linker.role,
        owner=old_linker.owner,
        target_id=old_linker.target_id,
        arguments=(*old_linker.arguments, "${BUILD}/obj/reader.obj"),
        inputs=tuple(sorted((*old_linker.inputs, "build/obj/reader.obj"), key=str.casefold)),
        directive_inputs=old_linker.directive_inputs,
        outputs=old_linker.outputs,
        depends_on=tuple(sorted((*old_linker.depends_on, reader.id), key=str.casefold)),
        timeout_seconds=old_linker.timeout_seconds,
    )
    graph = ProducerGraphDocument(
        schema_version=graph.schema_version,
        source_topology_digest=source_topology_digest(item.path for item in manifest.entries),
        toolchain_lock_digest=graph.toolchain_lock_digest,
        path_profile_id=graph.path_profile_id,
        extractor=graph.extractor,
        nodes=(compiler, reader, linker),
    )
    clean_inputs = tuple(
        sorted(
            (*snapshot.clean_source_inputs, CleanSourceInput(reader_path, payload)),
            key=lambda item: item.path.casefold(),
        )
    )
    return bundle, graph, snapshot.project_source_pairs, clean_inputs


@pytest.mark.parametrize(
    "reader_payload",
    (
        b'#include "unit.cpp"\n',
        b'int prefix;\r#include "unit.cpp"\r',
        b'int prefix;\r\n#include "unit.cpp"\r\n',
    ),
)
def test_strict_overlaid_source_secondary_include_widens_the_sparse_plan(
    tmp_path: Path,
    reader_payload: bytes,
) -> None:
    bundle, graph, _overlay, snapshot = _strict_project_overlay_authority(tmp_path)
    bundle, graph, pairs, clean_inputs = _with_secondary_compiler_reader(
        bundle,
        graph,
        snapshot,
        payload=reader_payload,
    )

    plan = plan_project_overlay_compiler_epochs(bundle, graph, pairs, clean_inputs)

    assert plan.audit_node_ids == frozenset({"compiler.app.0000", "compiler.app.0001"})
    assert any(
        reason.startswith("textual-secondary:src/reader.cpp:")
        for reason in plan.reader_closure_fallbacks
    )


@pytest.mark.parametrize(
    "force_include_arguments",
    (
        ("/FI${SOURCE}/src/unit.cpp",),
        ("/FI", "${SOURCE}/src/unit.cpp"),
    ),
)
def test_strict_overlaid_source_force_include_widens_the_sparse_plan(
    tmp_path: Path,
    force_include_arguments: tuple[str, ...],
) -> None:
    bundle, graph, _overlay, snapshot = _strict_project_overlay_authority(tmp_path)
    bundle, graph, pairs, clean_inputs = _with_secondary_compiler_reader(
        bundle,
        graph,
        snapshot,
        payload=b"int reader;\n",
        leading_arguments=force_include_arguments,
    )

    plan = plan_project_overlay_compiler_epochs(bundle, graph, pairs, clean_inputs)

    assert plan.audit_node_ids == frozenset({"compiler.app.0000", "compiler.app.0001"})
    assert any(
        reason.startswith("forced-secondary:compiler.app.0001:")
        for reason in plan.reader_closure_fallbacks
    )


def test_dynamic_include_widens_the_sparse_plan(tmp_path: Path) -> None:
    bundle, graph, _overlay, snapshot = _strict_project_overlay_authority(tmp_path)
    bundle, graph, pairs, clean_inputs = _with_secondary_compiler_reader(
        bundle,
        graph,
        snapshot,
        payload=b"#include SELECTED_SOURCE\n",
    )

    plan = plan_project_overlay_compiler_epochs(bundle, graph, pairs, clean_inputs)

    assert plan.audit_node_ids == frozenset({"compiler.app.0000", "compiler.app.0001"})
    assert "dynamic-include:src/reader.cpp" in plan.reader_closure_fallbacks


def test_toolchain_header_secondary_include_widens_the_sparse_plan(tmp_path: Path) -> None:
    bundle, graph, _overlay, snapshot = _strict_project_overlay_authority(tmp_path)
    bundle, graph, pairs, clean_inputs = _with_secondary_compiler_reader(
        bundle,
        graph,
        snapshot,
        payload=b"int reader;\n",
    )

    plan = plan_project_overlay_compiler_epochs(
        bundle,
        graph,
        pairs,
        clean_inputs,
        secondary_reader_payloads={"toolchain/include/hostile.h": b'#include "unit.cpp"\n'},
    )

    assert plan.audit_node_ids == frozenset({"compiler.app.0000", "compiler.app.0001"})
    assert any(
        reason.startswith("textual-secondary:toolchain/include/hostile.h:")
        for reason in plan.reader_closure_fallbacks
    )


def test_empty_toolchain_reader_evidence_widens_the_sparse_plan(tmp_path: Path) -> None:
    bundle, graph, _overlay, snapshot = _strict_project_overlay_authority(tmp_path)
    bundle, graph, pairs, clean_inputs = _with_secondary_compiler_reader(
        bundle,
        graph,
        snapshot,
        payload=b"int reader;\n",
    )
    include_tree = InputTreeReceipt(
        id="compiler-includes",
        path="include",
        entry_count=1,
        max_depth=0,
        membership_digest=Digest.from_bytes(b"include membership"),
        content_digest=Digest.from_bytes(b"include content"),
    )
    bundle = bundle.model_copy(
        update={
            "toolchain_lock": bundle.toolchain_lock.model_copy(
                update={"input_trees": (include_tree,)}
            )
        }
    )

    plan = plan_project_overlay_compiler_epochs(
        bundle,
        graph,
        pairs,
        clean_inputs,
        secondary_reader_payloads={},
    )

    assert plan.audit_node_ids == frozenset({"compiler.app.0000", "compiler.app.0001"})
    assert plan.reader_closure_fallbacks == ("toolchain-include-namespace-unavailable",)


def test_resource_reader_closure_rejects_an_overlaid_header_read(tmp_path: Path) -> None:
    bundle, graph, _overlay, _snapshot = _strict_project_overlay_authority(tmp_path)
    compiler = next(node for node in graph.nodes if node.role is ProducerRole.COMPILER)
    linker = next(node for node in graph.nodes if node.role is ProducerRole.LINKER)
    resource = ProducerNode(
        id="resource.app.0001",
        role=ProducerRole.RESOURCE,
        owner="app",
        arguments=("/fo${BUILD}/res/app.res", "${SOURCE}/res/app.rc"),
        inputs=("source/res/app.rc",),
        outputs=("build/res/app.res",),
    )
    graph = ProducerGraphDocument(
        schema_version=graph.schema_version,
        source_topology_digest=graph.source_topology_digest,
        toolchain_lock_digest=graph.toolchain_lock_digest,
        path_profile_id=graph.path_profile_id,
        extractor=graph.extractor,
        nodes=(compiler, linker, resource),
    )
    source_root = bundle.spec.paths.source
    source_path = source_root + r"\res\app.rc"
    overlaid_header = source_root + r"\include\helper.h"
    header = b"class Value {};\n"
    receipt = ResourceDependencyReceipt(
        source_path,
        (
            ResourceRead(
                source_path,
                Digest.from_bytes(b'#include "../include/helper.h"\n'),
                len(b'#include "../include/helper.h"\n'),
                IncludeOrigin.PROJECT_SOURCE,
                ResourceReadKind.ROOT,
                None,
            ),
            ResourceRead(
                overlaid_header,
                Digest.from_bytes(header),
                len(header),
                IncludeOrigin.PROJECT_SOURCE,
                ResourceReadKind.INCLUDE,
                source_path,
            ),
        ),
    )

    with pytest.raises(ClassicProjectError, match="secondary reader"):
        _project_overlay_resource_reader_closure(
            source_root=source_root,
            source_pairs=(
                ProjectOverlaySourcePair(
                    "include/helper.h",
                    header,
                    b"class Fresh {};\n" + header,
                ),
            ),
            graph=graph,
            receipts={resource.id: receipt},
        )


def test_strict_epoch_plan_compiles_only_the_exact_source_owner(tmp_path: Path) -> None:
    bundle, graph, _overlay, snapshot = _strict_project_overlay_authority(tmp_path)

    plan = plan_project_overlay_compiler_epochs(
        bundle,
        graph,
        snapshot.project_source_pairs,
        snapshot.clean_source_inputs,
    )

    assert plan.audit_node_ids == frozenset({"compiler.app.0000"})
    assert plan.runtime_projection_node_ids == frozenset()
    assert plan.declaration_outputs == {
        "src/unit.cpp": snapshot.project_source_pairs[0].effective_payload
    }
    assert plan.declaration_leaf_keys == {"overlay.project": (("op_function", 0),)}


def test_unreachable_helper_generator_in_a_header_fails_planning(tmp_path: Path) -> None:
    bundle, graph, original, _donor, _consumer, unit, _effective = _base_authority(
        tmp_path,
        generated_carrier=False,
    )
    header_path = "include/helper.h"
    clean = b"class Value {};\n"
    fragment = b"void FreshHelper()\n{\n\tValue local;\n}\n"
    effective = fragment + clean
    output = {
        "path": header_path,
        "clean": Digest.from_bytes(clean).value,
        "effective": Digest.from_bytes(effective).value,
        "size": len(effective),
        "ops": [
            {
                "op": "insert",
                "anchor": {
                    "ctx": _seat_digest(["<SEAT>", "class", "Value", "{", "}", ";"]),
                    "b": 0,
                    "a": 5,
                    "at": "start",
                },
                "gen": {
                    "k": "local_probe",
                    "function_identifier": "FreshHelper",
                    "local_identifier": "local",
                    "local_type": "Value",
                    "operation": "emit_local_object_destructor",
                },
            }
        ],
    }
    values = {item.name: item.value for item in original.parameters}
    values["outputs"] = [output]
    values["semantic_claims"] = {"schema": 1, "bindings": []}
    overlay = original.model_copy(
        update={
            "parameters": tuple(
                ClassicField(name=name, value=value) for name, value in sorted(values.items())
            )
        }
    )
    manifest = SourceManifestDocument(
        schema_version=3,
        complete=True,
        entries=(
            SourceManifestEntry(
                path=header_path,
                size=len(clean),
                digest=Digest.from_bytes(clean),
            ),
            SourceManifestEntry(
                path="src/unit.cpp",
                size=len(unit),
                digest=Digest.from_bytes(unit),
            ),
        ),
    )
    assert bundle.build_plan is not None
    bundle = bundle.model_copy(
        update={
            "source_manifest": manifest,
            "build_plan": bundle.build_plan.model_copy(
                update={
                    "source_manifest_digest": source_manifest_digest(manifest),
                    "source_overlay_digest": Digest.from_bytes(
                        canonical_json(overlay.model_dump(mode="json"))
                    ),
                }
            ),
            "intervention_documents": (
                bundle.intervention_documents[0].model_copy(update={"interventions": (overlay,)}),
                *bundle.intervention_documents[1:],
            ),
        }
    )
    graph = graph.model_copy(
        update={
            "source_topology_digest": source_topology_digest(item.path for item in manifest.entries)
        }
    )

    with pytest.raises(ClassicSemanticError, match="header helpers are unsupported"):
        plan_project_overlay_compiler_epochs(
            bundle,
            graph,
            (ProjectOverlaySourcePair(header_path, clean, effective),),
            (
                CleanSourceInput(header_path, clean),
                CleanSourceInput("src/unit.cpp", unit),
            ),
        )


def test_compiler_epoch_preflight_recomputes_and_binds_the_sparse_plan(
    tmp_path: Path,
) -> None:
    bundle, graph, _overlay, snapshot = _strict_project_overlay_authority(tmp_path)
    assert snapshot.counterfactual_namespace_id is not None

    trace = validate_project_overlay_compiler_epoch(
        bundle,
        graph,
        compiler_products=snapshot.compiler_products,
        project_source_pairs=snapshot.project_source_pairs,
        counterfactual_compiler_audits=snapshot.counterfactual_compiler_audits,
        counterfactual_namespace_id=snapshot.counterfactual_namespace_id,
        clean_source_inputs=snapshot.clean_source_inputs,
        compiler_namespaces=snapshot.compiler_namespaces,
    )

    assert trace["theorem"] == "sparse-project-overlay-compiler-epoch-preflight-v1"
    assert trace["audit_node_ids"] == ["compiler.app.0000"]
    assert len(trace["compiler_audits"]) == 1  # type: ignore[arg-type]


def test_unused_integral_typedef_binds_the_complete_census_theorem(tmp_path: Path) -> None:
    bundle, graph, overlay, snapshot = _typedef_overlay_authority(tmp_path)

    result = prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})

    epoch = result.trace[overlay.id]["project_overlay_epoch"]  # type: ignore[index]
    assert epoch["compiler_audits"] == []  # type: ignore[index]
    source = epoch["source_validation"]  # type: ignore[index]
    assert source["unused_typedefs"] == [  # type: ignore[index]
        {
            "theorem": "complete-census-fresh-unused-typedef-int-v1",
            "identifier": "FreshAlias",
            "aliased_type": "int",
            "source_path": "src/unit.cpp",
            "clean_occurrences": 0,
            "effective_occurrences": 1,
            "closed_declaration_boundary": True,
            "lexical_brace_depth": 0,
            "macro_sensitive_tokens": ["typedef", "int", "FreshAlias"],
        }
    ]


def test_unused_integral_typedef_needs_no_counterfactual_object_for_line_value_drift(
    tmp_path: Path,
) -> None:
    clean_object = _add_coff_line_table(
        _coff_object(
            "_main",
            reference="_dep",
            body_payload=b"\xe8\0\0\0\0\xc3",
            relocation_offset_in_section=1,
            relocation_type=20,
        ),
        ((0, 0), (0, 17)),
    )
    effective_object = _patch_coff_line_record(clean_object, 1, line=29)
    bundle, graph, overlay, snapshot = _typedef_overlay_authority(
        tmp_path,
        clean_object=clean_object,
        effective_object=effective_object,
    )

    result = prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})

    epoch = result.trace[overlay.id]["project_overlay_epoch"]  # type: ignore[index]
    assert epoch["compiler_audits"] == []  # type: ignore[index]


def test_unused_typedef_rejects_nonintegral_closed_form(tmp_path: Path) -> None:
    bundle, graph, _overlay, snapshot = _typedef_overlay_authority(
        tmp_path,
        aliased_type="long",
    )

    with pytest.raises(ClassicSemanticError, match="clean-backed exact 'typedef int'"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_unused_typedef_rejects_a_generated_use(tmp_path: Path) -> None:
    bundle, graph, _overlay, snapshot = _typedef_overlay_authority(
        tmp_path,
        used_by_generated_member=True,
    )

    with pytest.raises(ClassicSemanticError, match="not target-closed and unused"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_unused_typedef_source_theorem_does_not_request_a_runtime_projection(
    tmp_path: Path,
) -> None:
    bundle, graph, _overlay, snapshot = _typedef_overlay_authority(
        tmp_path,
        effective_object=_coff_object("_main", body_payload=b"\xb8\x01\0\0\0\xc3"),
    )

    result = prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})

    epoch = result.trace["overlay.project"]["project_overlay_epoch"]  # type: ignore[index]
    assert epoch["compiler_audits"] == []  # type: ignore[index]


@pytest.mark.parametrize("seat_kind", ("block-entry", "block-exit"))
def test_unused_integral_typedef_accepts_a_closed_nested_declaration_boundary(
    tmp_path: Path,
    seat_kind: str,
) -> None:
    clean = b"int main() {\n\treturn 0;\n}\n"
    if seat_kind == "block-entry":
        seat = clean.index(b"\treturn")
        before_tokens = ["int", "main", "(", ")", "{"]
        after_tokens = ["return", "0", ";", "}"]
    else:
        seat = clean.index(b"}")
        before_tokens = ["return", "0", ";"]
        after_tokens = ["}"]
    bundle, graph, overlay, snapshot = _typedef_seat_overlay_authority(
        tmp_path,
        clean=clean,
        seat=seat,
        before_tokens=before_tokens,
        after_tokens=after_tokens,
    )

    result = prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})

    source = result.trace[overlay.id]["project_overlay_epoch"]["source_validation"]  # type: ignore[index]
    theorem = source["unused_typedefs"][0]  # type: ignore[index]
    assert theorem["theorem"] == "complete-census-fresh-unused-typedef-int-v1"
    assert theorem["lexical_brace_depth"] == 1
    assert theorem["closed_declaration_boundary"] is True


@pytest.mark.parametrize(
    ("clean", "seat_marker", "before_tokens", "after_tokens"),
    (
        (
            b"int main() {\n\tif (flag)\n\t\treturn 1;\n}\n",
            b"\t\treturn",
            ["if", "(", "flag", ")"],
            ["return", "1", ";"],
        ),
        (
            b"int main() {\n\tif (flag) { return 1; }\n\telse { return 0; }\n}\n",
            b"\telse",
            ["return", "1", ";", "}"],
            ["else", "{", "return"],
        ),
        (
            b"int main() {\n\tdo { run(); }\n\twhile (again());\n}\n",
            b"\twhile",
            ["run", "(", ")", ";", "}"],
            ["while", "(", "again"],
        ),
        (
            b"int main() { return choose(flag && value, 0); }\n",
            b"value",
            ["choose", "(", "flag", "&&"],
            ["value", ",", "0", ")"],
        ),
        (
            b"int main() {\nlabel:\n\treturn 0;\n}\n",
            b"\treturn",
            ["label", ":"],
            ["return", "0", ";"],
        ),
    ),
)
def test_unused_typedef_rejects_control_expression_and_label_seats(
    tmp_path: Path,
    clean: bytes,
    seat_marker: bytes,
    before_tokens: list[str],
    after_tokens: list[str],
) -> None:
    bundle, graph, _overlay, snapshot = _typedef_seat_overlay_authority(
        tmp_path,
        clean=clean,
        seat=clean.index(seat_marker),
        before_tokens=before_tokens,
        after_tokens=after_tokens,
    )

    with pytest.raises(ClassicSemanticError, match="closed declaration boundary"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_unused_typedef_rejects_a_clean_source_occurrence(tmp_path: Path) -> None:
    clean = b"int FreshAlias;\n"
    bundle, graph, _overlay, snapshot = _typedef_seat_overlay_authority(
        tmp_path,
        clean=clean,
        seat=0,
        before_tokens=[],
        after_tokens=["int", "FreshAlias", ";"],
    )

    with pytest.raises(ClassicSemanticError, match="not globally fresh"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_unused_typedef_rejects_preprocessor_capture_of_int(tmp_path: Path) -> None:
    clean = b"#define int long\nint value;\n"
    seat = clean.index(b"int value")
    bundle, graph, _overlay, snapshot = _typedef_seat_overlay_authority(
        tmp_path,
        clean=clean,
        seat=seat,
        before_tokens=["#", "define", "int", "long"],
        after_tokens=["int", "value", ";"],
    )

    with pytest.raises(ClassicSemanticError, match="macro-capture"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_unused_typedef_rejects_compiler_command_line_macro_capture(tmp_path: Path) -> None:
    bundle, graph, _overlay, snapshot = _typedef_overlay_authority(tmp_path)
    compiler = next(node for node in graph.nodes if node.role is ProducerRole.COMPILER)
    changed_compiler = compiler.model_copy(
        update={"arguments": ("/DFreshAlias=Captured", *compiler.arguments)}
    )
    graph = graph.model_copy(
        update={
            "nodes": tuple(
                changed_compiler if node.id == compiler.id else node for node in graph.nodes
            )
        }
    )
    product = snapshot.compiler_products[0]
    assert product.compiler_invocation is not None

    def changed_invocation(value: CompilerEpochInvocation) -> CompilerEpochInvocation:
        changed = replace(value, arguments=changed_compiler.arguments)
        return replace(changed, invocation_digest=compiler_epoch_invocation_digest(changed))

    snapshot = _bound_snapshot(
        graph,
        replace(
            snapshot,
            compiler_products=(
                replace(
                    product,
                    compiler_invocation=changed_invocation(product.compiler_invocation),
                ),
            ),
        ),
    )

    with pytest.raises(ClassicSemanticError, match="macro-capture"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_generated_epoch_namespace_is_explicitly_referenced_and_validated(
    tmp_path: Path,
) -> None:
    bundle, graph, _overlay, _donor, _consumer, clean, effective = _base_authority(
        tmp_path, generated_carrier=True
    )
    compiler_tool = next(item for item in bundle.toolchain_lock.tools if "compiler" in item.roles)
    bundle = bundle.model_copy(
        update={
            "toolchain_lock": bundle.toolchain_lock.model_copy(
                update={"profile_sources": (), "tools": (compiler_tool,)}
            )
        }
    )
    node = next(item for item in graph.nodes if item.id == "compiler.app.0001")
    invocation, namespace = _compiler_invocation(
        bundle,
        graph,
        node,
        (
            CompilerSourceRead(
                "source/src/carrier.cpp",
                Digest.from_bytes(effective),
                len(effective),
                None,
                effective,
            ),
            CompilerSourceRead(
                "source/src/unit.cpp",
                Digest.from_bytes(clean),
                len(clean),
                None,
                clean,
            ),
        ),
        namespace_id="generated",
    )

    validated = _validate_compiler_namespaces(
        bundle=bundle,
        evidences=(namespace,),
        referenced_ids=frozenset({"generated"}),
        sensitive_identifiers=frozenset(),
    )
    _validate_compiler_invocation(
        bundle=bundle,
        graph=graph,
        node=node,
        invocation=invocation,
        namespaces=validated,
        epoch="generated",
    )
    with pytest.raises(ClassicSemanticError, match="namespace universe differs"):
        _validate_compiler_namespaces(
            bundle=bundle,
            evidences=(namespace,),
            referenced_ids=frozenset(),
            sensitive_identifiers=frozenset(),
        )


def test_closed_source_theorem_accepts_only_a_proven_equivalent_code_encoding(
    tmp_path: Path,
) -> None:
    clean = b"int main() {\n\treturn 0;\n}\n"
    bundle, graph, overlay, snapshot = _empty_scope_overlay_authority(
        tmp_path,
        clean=clean,
        seat=clean.index(b"return"),
        before_tokens=["{"],
        after_tokens=["return", "0", ";"],
        clean_object=_coff_object("_main", body_payload=b"\x31\xc0\xc3"),
        effective_object=_coff_object("_main", body_payload=b"\x33\xc0\xc3"),
    )

    result = prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})

    audit = result.trace[overlay.id]["project_overlay_epoch"]["compiler_audits"][0]  # type: ignore[index]
    theorem = audit["coff_semantic_theorem"]  # type: ignore[index]
    assert theorem["changed_code_section_count"] == 1  # type: ignore[index]
    assert theorem["theorem"] == "closed-source-compiler-congruence-coff-envelope-v1"  # type: ignore[index]


def test_logic_changing_code_is_not_an_admitted_encoding_delta(tmp_path: Path) -> None:
    clean = b"int main() {\n\treturn 0;\n}\n"
    bundle, graph, _overlay, snapshot = _empty_scope_overlay_authority(
        tmp_path,
        clean=clean,
        seat=clean.index(b"return"),
        before_tokens=["{"],
        after_tokens=["return", "0", ";"],
        clean_object=_coff_object("_main", body_payload=b"\x31\xc0\xc3"),
        effective_object=_coff_object("_main", body_payload=b"\xb8\x01\x00\x00\x00\xc3"),
    )

    with pytest.raises(ClassicSemanticError, match="closed COFF semantic envelope"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_closed_source_theorem_binds_external_definition_value(tmp_path: Path) -> None:
    clean = b"int main() {\n\treturn 0;\n}\n"
    clean_object = _coff_object("_main", body_payload=b"\x40\xc3")
    effective_object = _patch_coff_symbol(clean_object, "_main", value=1)
    bundle, graph, _overlay, snapshot = _empty_scope_overlay_authority(
        tmp_path,
        clean=clean,
        seat=clean.index(b"return"),
        before_tokens=["{"],
        after_tokens=["return", "0", ";"],
        clean_object=clean_object,
        effective_object=effective_object,
    )

    with pytest.raises(ClassicSemanticError, match="closed COFF semantic envelope"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


@pytest.mark.parametrize("section_name", (".pdata", ".xdata$x"))
def test_closed_source_theorem_binds_compiler_control_bytes(
    tmp_path: Path,
    section_name: str,
) -> None:
    clean = b"int main() {\n\treturn 0;\n}\n"
    bundle, graph, _overlay, snapshot = _empty_scope_overlay_authority(
        tmp_path,
        clean=clean,
        seat=clean.index(b"return"),
        before_tokens=["{"],
        after_tokens=["return", "0", ";"],
        clean_object=_coff_object(
            "_main",
            section_name=section_name,
            body_payload=b"\x01\x02\x03\x04",
        ),
        effective_object=_coff_object(
            "_main",
            section_name=section_name,
            body_payload=b"\xff\xee\xdd\xcc",
        ),
    )

    with pytest.raises(ClassicSemanticError, match="closed COFF semantic envelope"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


@pytest.mark.parametrize(
    ("clean", "seat_token", "before_tokens", "after_tokens"),
    (
        (
            b"int flag(); int call(); int main() { if (flag()) call(); return 0; }\n",
            b"call(); return",
            ["flag", "(", ")", ")"],
            ["call", "(", ")", ";"],
        ),
        (
            b"int flag(); int call(); int main() { if (flag()) call(); else call(); }\n",
            b"else call",
            ["call", "(", ")", ";"],
            ["else", "call", "(", ")"],
        ),
        (
            b"int flag(); int call(); int main() { while (flag()) call(); }\n",
            b"call(); }",
            ["flag", "(", ")", ")"],
            ["call", "(", ")", ";"],
        ),
        (
            b"int flag(); int call(); int main() { flag() && call(); }\n",
            b"call(); }",
            [")", "&&"],
            ["call", "(", ")", ";"],
        ),
    ),
)
def test_executable_overlay_rejects_control_expression_and_dangling_else_seats(
    tmp_path: Path,
    clean: bytes,
    seat_token: bytes,
    before_tokens: list[str],
    after_tokens: list[str],
) -> None:
    seat = clean.index(seat_token)
    bundle, graph, _overlay, snapshot = _empty_scope_overlay_authority(
        tmp_path,
        clean=clean,
        seat=seat,
        before_tokens=before_tokens,
        after_tokens=after_tokens,
    )

    with pytest.raises(ClassicSemanticError, match="compound-statement boundary"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


@pytest.mark.parametrize(
    "mutation",
    (
        "definition",
        "dependency",
        "common",
        "weak",
        "comdat-selection",
        "comdat-association",
        "directive",
        "initialized-data",
        "crt-root",
        "tls-root",
    ),
)
def test_coff_theorem_rejects_linkage_relocation_control_and_data_mutations(
    tmp_path: Path,
    mutation: str,
) -> None:
    call = dict(
        body_payload=b"\xe8\0\0\0\0\xc3",
        relocation_offset_in_section=1,
        relocation_type=20,
    )
    if mutation == "definition":
        clean_object = _coff_object("_main", reference="_aux", **call)
        effective_object = _patch_coff_symbol(clean_object, "_aux", section=1)
    elif mutation == "dependency":
        clean_object = _coff_object("_main", reference="_dep1", **call)
        effective_object = _coff_object("_main", reference="_dep2", **call)
    elif mutation == "common":
        clean_object = _coff_object("_main", reference="_item", **call)
        effective_object = _patch_coff_symbol(clean_object, "_item", value=4)
    elif mutation == "weak":
        clean_object = _weak_reference_object(characteristics=2)
        effective_object = _weak_reference_object(characteristics=3)
    elif mutation == "comdat-selection":
        clean_object = _coff_object("_main")
        effective_object = _patch_comdat_auxiliary(clean_object, selection=3)
    elif mutation == "comdat-association":
        clean_object = _coff_object("_main")
        effective_object = _patch_comdat_auxiliary(clean_object, associated=1)
    elif mutation == "directive":
        clean_object = _coff_object("_dir", section_name=".drectve", body_payload=b"/include:_a ")
        effective_object = _coff_object(
            "_dir", section_name=".drectve", body_payload=b"/include:_b "
        )
    elif mutation == "initialized-data":
        clean_object = _coff_object(
            "_data", section_name=".rdata", body_payload=b"\x01\x02\x03\x04"
        )
        effective_object = _coff_object(
            "_data", section_name=".rdata", body_payload=b"\x01\x02\x03\x05"
        )
    elif mutation == "crt-root":
        clean_object = _coff_object("_root", section_name=".CRT", body_payload=b"\0\0\0\0")
        effective_object = _coff_object("_root", section_name=".CRT", body_payload=b"\1\0\0\0")
    else:
        clean_object = _coff_object("_root", section_name=".tls", body_payload=b"\0\0\0\0")
        effective_object = _coff_object("_root", section_name=".tls", body_payload=b"\1\0\0\0")
    clean = b"int main() {\n\treturn 0;\n}\n"
    bundle, graph, _overlay, snapshot = _empty_scope_overlay_authority(
        tmp_path,
        clean=clean,
        seat=clean.index(b"return"),
        before_tokens=["{"],
        after_tokens=["return", "0", ";"],
        clean_object=clean_object,
        effective_object=effective_object,
    )

    with pytest.raises(ClassicSemanticError, match="closed COFF semantic envelope"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_relocation_addend_change_is_not_a_code_encoding_delta(tmp_path: Path) -> None:
    clean_object = _coff_object(
        "_main",
        reference="_dep",
        body_payload=b"\xe8\0\0\0\0\xc3",
        relocation_offset_in_section=1,
        relocation_type=20,
    )
    effective_object = _coff_object(
        "_main",
        reference="_dep",
        body_payload=b"\xe8\1\0\0\0\xc3",
        relocation_offset_in_section=1,
        relocation_type=20,
    )
    bundle, graph, _overlay, snapshot = _strict_project_overlay_authority(
        tmp_path,
        counterfactual_object=clean_object,
        effective_object=effective_object,
    )

    with pytest.raises(ClassicSemanticError, match="closed COFF semantic envelope"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_object_swap_without_current_run_rebinding_fails_before_semantics(
    tmp_path: Path,
) -> None:
    bundle, graph, _overlay, snapshot = _certified_project_overlay_authority(tmp_path)
    product = replace(
        snapshot.compiler_products[0],
        payload=_coff_object("_main", body_payload=b"\xb8\x01\0\0\0\xc3"),
    )

    with pytest.raises(ClassicSemanticError, match="run binding"):
        prove_source_overlay_semantics(
            bundle,
            graph,
            replace(snapshot, compiler_products=(product,)),
            semantic_contracts={},
        )


def test_compiler_congruence_rejects_an_environment_epoch_change(tmp_path: Path) -> None:
    bundle, graph, _overlay, snapshot = _strict_project_overlay_authority(tmp_path)
    product = snapshot.compiler_products[0]
    assert product.compiler_invocation is not None
    changed = replace(
        product.compiler_invocation,
        environment_digest=Digest.from_bytes(b"different compiler environment"),
    )
    changed = replace(changed, invocation_digest=compiler_epoch_invocation_digest(changed))
    snapshot = _bound_snapshot(
        graph,
        replace(
            snapshot,
            compiler_products=(replace(product, compiler_invocation=changed),),
        ),
    )

    with pytest.raises(ClassicSemanticError, match="counterfactual/effective invocation differs"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_compiler_congruence_rehashes_every_read_payload(tmp_path: Path) -> None:
    bundle, graph, _overlay, snapshot = _strict_project_overlay_authority(tmp_path)
    namespace = next(
        item for item in snapshot.compiler_namespaces if item.namespace_id == "counterfactual"
    )
    clean_read = namespace.members[0]
    changed_namespace = replace(
        namespace,
        members=(replace(clean_read, payload=b"tampered"), *namespace.members[1:]),
    )
    # Payload bytes are transitively committed by their digest/size, so this
    # mutation intentionally leaves the canonical run binding unchanged.
    snapshot = replace(
        snapshot,
        compiler_namespaces=(
            changed_namespace,
            *(item for item in snapshot.compiler_namespaces if item is not namespace),
        ),
    )

    with pytest.raises(ClassicSemanticError, match="member 0 bytes changed"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_compiler_congruence_rejects_macro_capture_from_exact_read_closure(
    tmp_path: Path,
) -> None:
    bundle, graph, _overlay, snapshot = _certified_project_overlay_authority(tmp_path)
    product = snapshot.compiler_products[0]
    assert product.compiler_invocation is not None
    compiler_payload = b"#define Spare Captured\n"
    tool = bundle.toolchain_lock.tools[0].model_copy(
        update={
            "digest": Digest.from_bytes(compiler_payload),
            "size": len(compiler_payload),
        }
    )
    toolchain_lock = bundle.toolchain_lock.model_copy(update={"tools": (tool,)})
    bundle = bundle.model_copy(update={"toolchain_lock": toolchain_lock})
    graph = graph.model_copy(
        update={"toolchain_lock_digest": toolchain_document_digest(toolchain_lock)}
    )

    changed_namespaces: list[CompilerNamespaceEvidence] = []
    by_id: dict[str, CompilerNamespaceEvidence] = {}
    for namespace in snapshot.compiler_namespaces:
        members = tuple(
            replace(
                item,
                digest=Digest.from_bytes(compiler_payload),
                size=len(compiler_payload),
                payload=compiler_payload,
            )
            if item.reference == "toolchain/bin/cl.exe"
            else item
            for item in namespace.members
        )
        changed_namespace = replace(namespace, members=members)
        changed_namespace = replace(
            changed_namespace,
            namespace_digest=compiler_namespace_evidence_digest(changed_namespace),
        )
        changed_namespaces.append(changed_namespace)
        by_id[namespace.namespace_id] = changed_namespace

    def changed_invocation(value: CompilerEpochInvocation) -> CompilerEpochInvocation:
        namespace = by_id[value.namespace_id]
        changed = replace(
            value,
            tool_digest=tool.digest,
            namespace_digest=namespace.namespace_digest,
            namespace_count=len(namespace.members),
        )
        return replace(changed, invocation_digest=compiler_epoch_invocation_digest(changed))

    changed_product = replace(
        product,
        compiler_invocation=changed_invocation(product.compiler_invocation),
    )
    snapshot = _bound_snapshot(
        graph,
        replace(
            snapshot,
            compiler_products=(changed_product,),
            compiler_namespaces=tuple(changed_namespaces),
        ),
    )

    with pytest.raises(ClassicSemanticError, match="macro-capture"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_compiler_congruence_rejects_an_undeclared_namespace_file(tmp_path: Path) -> None:
    bundle, graph, _overlay, snapshot = _certified_project_overlay_authority(tmp_path)
    product = snapshot.compiler_products[0]
    assert product.compiler_invocation is not None
    header = b"struct HeaderOnly;\n"
    toolchain_read = CompilerSourceRead(
        "toolchain/include/extra.h",
        Digest.from_bytes(header),
        len(header),
        None,
        header,
    )
    namespace = next(
        item for item in snapshot.compiler_namespaces if item.namespace_id == "effective"
    )
    changed_namespace = replace(namespace, members=(*namespace.members, toolchain_read))
    changed_namespace = replace(
        changed_namespace,
        namespace_digest=compiler_namespace_evidence_digest(changed_namespace),
    )
    changed_invocation = replace(
        product.compiler_invocation,
        namespace_digest=changed_namespace.namespace_digest,
        namespace_count=len(changed_namespace.members),
    )
    changed_invocation = replace(
        changed_invocation,
        invocation_digest=compiler_epoch_invocation_digest(changed_invocation),
    )
    changed_product = replace(product, compiler_invocation=changed_invocation)
    snapshot = _bound_snapshot(
        graph,
        replace(
            snapshot,
            compiler_products=(changed_product,),
            compiler_namespaces=tuple(
                changed_namespace if item is namespace else item
                for item in snapshot.compiler_namespaces
            ),
        ),
    )

    with pytest.raises(ClassicSemanticError, match="undeclared files"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


@pytest.mark.parametrize(
    "tree_member",
    (
        "detail/fresh.ipp",
        "detail/fresh.tcc",
        "detail/fresh",
    ),
)
def test_global_declaration_census_covers_all_locked_include_tree_sources(
    tmp_path: Path,
    tree_member: str,
) -> None:
    bundle, graph, _overlay, _snapshot = _certified_project_overlay_authority(tmp_path)
    payload = b"class FreshGlobal {};\n"
    read = CompilerSourceRead(
        f"toolchain/include/{tree_member}",
        Digest.from_bytes(payload),
        len(payload),
        None,
        payload,
    )
    statement = _portable_tree_statement(
        relative_root="include",
        files={tree_member: read},
    )
    tree = InputTreeReceipt(
        id="compiler-includes",
        path="include",
        entry_count=int(statement["entry_count"]),
        max_depth=int(statement["max_depth"]),
        membership_digest=Digest(value=str(statement["membership_digest"])),
        content_digest=Digest(value=str(statement["content_digest"])),
    )
    bundle = bundle.model_copy(
        update={"toolchain_lock": bundle.toolchain_lock.model_copy(update={"input_trees": (tree,)})}
    )
    compiler = next(node for node in graph.nodes if node.role is ProducerRole.COMPILER)
    _invocation, namespace = _compiler_invocation(
        bundle,
        graph,
        compiler,
        (read,),
        namespace_id="effective",
    )

    with pytest.raises(
        ClassicSemanticError,
        match="generated global declaration identifier already exists",
    ):
        _validate_compiler_namespaces(
            bundle=bundle,
            evidences=(namespace,),
            referenced_ids=frozenset({"effective"}),
            sensitive_identifiers=frozenset(),
            global_declaration_identifiers=frozenset({"FreshGlobal"}),
        )


def test_compiler_congruence_rejects_casefold_namespace_aliases(tmp_path: Path) -> None:
    bundle, graph, _overlay, snapshot = _certified_project_overlay_authority(tmp_path)
    product = snapshot.compiler_products[0]
    assert product.compiler_invocation is not None
    namespace = next(
        item for item in snapshot.compiler_namespaces if item.namespace_id == "effective"
    )
    primary = next(item for item in namespace.members if item.reference == "source/src/unit.cpp")
    alias = replace(primary, reference="source/SRC/unit.cpp")
    members = tuple(
        sorted(
            (*namespace.members, alias),
            key=lambda item: (item.reference.casefold(), item.reference),
        )
    )
    changed_namespace = replace(namespace, members=members)
    changed_namespace = replace(
        changed_namespace,
        namespace_digest=compiler_namespace_evidence_digest(changed_namespace),
    )
    changed_invocation = replace(
        product.compiler_invocation,
        namespace_digest=changed_namespace.namespace_digest,
        namespace_count=len(changed_namespace.members),
    )
    changed_invocation = replace(
        changed_invocation,
        invocation_digest=compiler_epoch_invocation_digest(changed_invocation),
    )
    changed_product = replace(product, compiler_invocation=changed_invocation)
    snapshot = _bound_snapshot(
        graph,
        replace(
            snapshot,
            compiler_products=(changed_product,),
            compiler_namespaces=tuple(
                changed_namespace if item is namespace else item
                for item in snapshot.compiler_namespaces
            ),
        ),
    )

    with pytest.raises(ClassicSemanticError, match=r"namespace .*census is not canonical"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


@pytest.mark.parametrize(
    ("type_spelling", "message"),
    (
        ("Guard", "dead-local theorem differs"),
        ("int*", "dead-local theorem differs"),
    ),
)
def test_dead_local_theorem_rejects_destructors_and_volatile_state(
    tmp_path: Path,
    type_spelling: str,
    message: str,
) -> None:
    clean = b"struct Guard { ~Guard(); }; int main() { return 0; }\n"
    seat = clean.index(b"return")
    bundle, graph, _overlay, snapshot = _function_overlay_authority(
        tmp_path,
        clean=clean,
        seat=seat,
        before_tokens=["{"],
        after_tokens=["return", "0", ";"],
        generator={
            "k": "local_ids",
            "function": "main",
            "identifiers": ["entropyLocal"],
            "type": type_spelling,
        },
        fragment=f"\t{type_spelling} entropyLocal;\n".encode("ascii"),
    )

    with pytest.raises(ClassicSemanticError, match=message):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


@pytest.mark.parametrize(
    ("clean", "type_spelling", "initialized", "message"),
    (
        (
            b"int main() { int value; return 0; }\n",
            "int",
            False,
            "scalar identity claim differs",
        ),
        (
            b"int main() { volatile int value = 0; return value; }\n",
            "volatile int",
            True,
            "not a proven integral type",
        ),
    ),
)
def test_noop_assignment_rejects_uninitialized_and_volatile_ub_boundaries(
    tmp_path: Path,
    clean: bytes,
    type_spelling: str,
    initialized: bool,
    message: str,
) -> None:
    seat = clean.index(b"return")
    bundle, graph, _overlay, snapshot = _function_overlay_authority(
        tmp_path,
        clean=clean,
        seat=seat,
        before_tokens=[";"],
        after_tokens=["return"],
        generator={"k": "noop_assign", "assignment_target": "value", "repeat": 1},
        fragment=b"\tvalue = value + 0;\n",
        bindings=[
            {
                "identifier": "value",
                "initialized": initialized,
                "type": type_spelling,
            }
        ],
    )

    with pytest.raises(ClassicSemanticError, match=message):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_dead_local_cannot_enter_a_for_initializer_expression(tmp_path: Path) -> None:
    clean = b"int main() { for (int i = 0; i < 1; ++i) {} return 0; }\n"
    seat = clean.index(b"int i")
    bundle, graph, _overlay, snapshot = _function_overlay_authority(
        tmp_path,
        clean=clean,
        seat=seat,
        before_tokens=["for", "("],
        after_tokens=["int", "i", "="],
        generator={
            "k": "local_ids",
            "function": "main",
            "identifiers": ["entropyLocal"],
            "type": "int",
        },
        fragment=b"\tint entropyLocal;\n",
    )

    with pytest.raises(ClassicSemanticError, match="compound-statement boundary"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_dead_local_rejects_inline_assembly_frame_observation(tmp_path: Path) -> None:
    clean = b"int main() { __asm { mov eax, esp } return 0; }\n"
    seat = clean.index(b"return")
    bundle, graph, _overlay, snapshot = _function_overlay_authority(
        tmp_path,
        clean=clean,
        seat=seat,
        before_tokens=["}"],
        after_tokens=["return", "0", ";"],
        generator={
            "k": "local_ids",
            "function": "main",
            "identifiers": ["entropyLocal"],
            "type": "int",
        },
        fragment=b"\tint entropyLocal;\n",
    )

    with pytest.raises(ClassicSemanticError, match="observed frame state"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("source-pair", "source-pair universe"),
        ("counterfactual-audit", "counterfactual compiler audit universe"),
        ("clean-census", "clean source input census"),
        ("namespace", "shared compiler namespace universe"),
        ("origin", "origin and counterfactual evidence"),
    ),
)
def test_certified_project_overlay_fails_closed_on_incomplete_epoch_evidence(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    bundle, graph, _overlay, snapshot = _strict_project_overlay_authority(tmp_path)
    if mutation == "source-pair":
        snapshot = _bound_snapshot(graph, replace(snapshot, project_source_pairs=()))
    elif mutation == "counterfactual-audit":
        snapshot = _bound_snapshot(graph, replace(snapshot, counterfactual_compiler_audits=()))
    elif mutation == "clean-census":
        snapshot = _bound_snapshot(graph, replace(snapshot, clean_source_inputs=()))
    elif mutation == "namespace":
        snapshot = _bound_snapshot(
            graph,
            replace(snapshot, compiler_namespaces=snapshot.compiler_namespaces[:1]),
        )
    else:
        snapshot = _bound_snapshot(
            graph,
            replace(
                snapshot,
                primary_sources=(
                    replace(
                        snapshot.primary_sources[0],
                        origin=PrimarySourceOrigin.EFFECTIVE_OVERLAY,
                    ),
                ),
            ),
        )
    with pytest.raises(ClassicSemanticError, match=message):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_certified_project_overlay_rejects_manifest_claim_as_a_verdict(
    tmp_path: Path,
) -> None:
    bundle, graph, overlay, snapshot = _certified_project_overlay_authority(tmp_path)
    values = {item.name: item.value for item in overlay.parameters}
    values["semantic_claims"] = {
        "schema": 1,
        "bindings": [
            {
                "kind": "semantic_equivalent",
                "leaf": 0,
                "operation": "src/unit.cpp#0",
                "verdict": True,
            }
        ],
    }
    changed = overlay.model_copy(
        update={
            "parameters": tuple(
                ClassicField(name=name, value=value) for name, value in sorted(values.items())
            )
        }
    )
    document = bundle.intervention_documents[0].model_copy(
        update={
            "interventions": (
                changed,
                *bundle.intervention_documents[0].interventions[1:],
            )
        }
    )
    bundle = bundle.model_copy(
        update={
            "intervention_documents": (
                document,
                *bundle.intervention_documents[1:],
            )
        }
    )

    with pytest.raises(ClassicSemanticError, match="unknown semantic claim"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_overlay_is_certified_only_through_clean_seed_and_typed_donor_lane(
    tmp_path: Path,
) -> None:
    bundle, graph, overlay, donor, consumer, clean, effective = _base_authority(
        tmp_path, generated_carrier=False
    )
    assert donor is not None and consumer is not None
    snapshot = _donor_snapshot(bundle, graph, donor, consumer, clean, effective)

    result = prove_source_overlay_semantics(
        bundle,
        graph,
        snapshot,
        semantic_contracts={consumer.family: _BINARY_CONTRACT},
    )

    proof = result.proofs[overlay.id]
    assert proof.validator_id == SOURCE_OVERLAY_VALIDATOR_ID
    assert proof.validator_digest == SOURCE_OVERLAY_VALIDATOR_DIGEST
    assert proof.obligations == SOURCE_OVERLAY_OBLIGATIONS
    assert result.trace[overlay.id]["discarded_outputs"] == []  # type: ignore[index]


@pytest.mark.parametrize(
    ("owner_target", "lane_target", "generated", "certified", "expected"),
    (
        ("owner", "owner", False, False, True),
        ("owner", "consumer", False, True, True),
        ("owner", "consumer", False, False, False),
        ("owner", "consumer", True, True, False),
    ),
)
def test_overlay_lane_sharing_is_limited_to_certified_ordinary_sources(
    owner_target: str,
    lane_target: str,
    generated: bool,
    certified: bool,
    expected: bool,
) -> None:
    owner = _OverlayOutputOwner("overlay.owner", owner_target, generated)
    assert (
        _overlay_lane_input_is_authorized(
            owner,
            lane_target,
            certified_project_overlay=certified,
        )
        is expected
    )


def test_certified_ordinary_overlay_feeds_a_cross_target_donor_lane_and_binds_its_trace(
    tmp_path: Path,
) -> None:
    bundle, graph, overlay, snapshot = _certified_project_overlay_authority(tmp_path)
    pair = snapshot.project_source_pairs[0]
    assert pair.clean_payload is not None

    unit_document = next(
        document
        for document in bundle.intervention_documents
        if document.translation_unit_id is not None
    )
    original_donor, original_consumer = unit_document.interventions
    assert isinstance(original_donor, ClassicRecipeIntervention)
    assert isinstance(original_consumer, ClassicRecipeIntervention)
    donor = original_donor.model_copy(
        update={
            "build_target": "config",
            "scope": Scope(target="config", translation_unit="tu.unit"),
        }
    )
    consumer = original_consumer.model_copy(
        update={
            "build_target": "config",
            "scope": Scope(
                target="config",
                translation_unit="tu.unit",
                function="?target@@YAHXZ",
            ),
        }
    )
    replacement_document = unit_document.model_copy(
        update={
            "target_id": "config",
            "build_target": "config",
            "interventions": (donor, consumer),
        }
    )
    intervention_documents = tuple(
        replacement_document if document is unit_document else document
        for document in bundle.intervention_documents
    )
    proof_documents = tuple(
        document.model_copy(update={"target_id": "config"})
        if document.translation_unit_id == "tu.unit"
        else document
        for document in bundle.proof_documents
    )
    assert bundle.build_plan is not None
    config_units = tuple(
        unit.model_copy(update={"target_id": "config", "build_target": "config"})
        for unit in bundle.build_plan.translation_units
    )
    bundle = bundle.model_copy(
        update={
            "spec": bundle.spec.model_copy(
                update={
                    "targets": (
                        *bundle.spec.targets,
                        TargetSpec(
                            id="config",
                            artifact="out/config.exe",
                            oracle="reference/config.exe",
                        ),
                    )
                }
            ),
            "build_plan": bundle.build_plan.model_copy(
                update={
                    "translation_units": config_units,
                    "target_gates": (
                        *bundle.build_plan.target_gates,
                        ClassicTargetGate(
                            target_id="config",
                            build_target="config",
                        ),
                    ),
                }
            ),
            "intervention_documents": intervention_documents,
            "proof_documents": proof_documents,
            "oracle_documents": (
                *bundle.oracle_documents,
                OracleDocument(
                    schema_version=3,
                    target_id="config",
                    image_size=1,
                    image_digest=Digest.from_bytes(b"y"),
                ),
            ),
        }
    )

    compiler = next(node for node in graph.nodes if node.role is ProducerRole.COMPILER)
    config_linker = ProducerNode(
        id="linker.config.0000",
        role=ProducerRole.LINKER,
        owner="config",
        target_id="config",
        arguments=(
            "/out:${BUILD}/out/config.exe",
            "${BUILD}/obj/unit.obj",
        ),
        inputs=("build/obj/unit.obj",),
        outputs=("build/out/config.exe",),
        depends_on=(compiler.id,),
    )
    graph = graph.model_copy(update={"nodes": (*graph.nodes, config_linker)})

    donor_snapshot = _donor_snapshot(
        bundle,
        graph,
        donor,
        consumer,
        pair.clean_payload,
        pair.effective_payload,
    )
    lane = replace(donor_snapshot.donor_lanes[0], target_id="config")
    snapshot = _bound_snapshot(
        graph,
        replace(
            snapshot,
            donor_lanes=(lane,),
            link_closures=(
                *snapshot.link_closures,
                TargetLinkClosure("config", (compiler.id,), demand_root_symbols=("_main",)),
            ),
        ),
    )

    result = prove_source_overlay_semantics(
        bundle,
        graph,
        snapshot,
        semantic_contracts={consumer.family: _BINARY_CONTRACT},
    )

    trace_lane = result.trace[overlay.id]["donor_lanes"][0]  # type: ignore[index]
    assert trace_lane["target"] == "config"  # type: ignore[index]
    assert trace_lane["donor"] == donor.id  # type: ignore[index]
    assert trace_lane["consumer"] == consumer.id  # type: ignore[index]
    assert trace_lane["overlay_inputs"] == [  # type: ignore[index]
        {
            "path": "src/unit.cpp",
            "digest": Digest.from_bytes(pair.effective_payload).model_dump(mode="json"),
            "size": len(pair.effective_payload),
        }
    ]


def _issued_candidate_material(
    intervention: ClassicRecipeIntervention,
    *,
    seed_input: bytes,
    binary_inputs: Mapping[str, bytes],
    source_inputs: Mapping[str, bytes],
    candidate_constraints: Mapping[str, object],
    output: bytes,
    validator_trace: Mapping[str, object],
) -> _ClassicCandidateSemanticMaterial:
    return _ClassicCandidateSemanticMaterial(
        intervention=intervention,
        seed_input=seed_input,
        binary_inputs=binary_inputs,
        source_inputs=source_inputs,
        candidate_constraints=candidate_constraints,
        output=output,
        validator_trace=validator_trace,
        _issuer=_CLASSIC_SEMANTIC_ISSUER,
    )


def _issued_donor_material(
    intervention: ClassicRecipeIntervention,
    *,
    donor_object: bytes,
    source_inputs: Mapping[str, bytes],
    compiler_statement: Mapping[str, object],
) -> _ClassicDonorSemanticMaterial:
    return _ClassicDonorSemanticMaterial(
        intervention=intervention,
        donor_object=donor_object,
        source_inputs=source_inputs,
        compiler_statement=compiler_statement,
        _issuer=_CLASSIC_SEMANTIC_ISSUER,
    )


def test_registry_covers_every_nonlegacy_closed_classic_family() -> None:
    assert set(CLASSIC_SEMANTIC_CONTRACTS) == set(ClassicRecipeFamily) - {
        ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION,
        ClassicRecipeFamily.ARCHIVE_ADMISSION,
    }


def test_semantic_issuers_reject_material_without_internal_provenance(
    tmp_path: Path,
) -> None:
    _bundle, _graph, _overlay, donor, consumer, _clean, _effective = _base_authority(
        tmp_path, generated_carrier=False
    )
    assert donor is not None and consumer is not None
    with pytest.raises(ClassicSemanticError, match=r"candidate.*internal provenance"):
        issue_classic_candidate_semantics(
            consumer,
            material=_ClassicCandidateSemanticMaterial(
                intervention=consumer,
                seed_input=b"seed object",
                binary_inputs={f"dependency:{donor.id}": b"donor object"},
                source_inputs={},
                candidate_constraints={},
                output=b"candidate object",
                validator_trace={"same_linked_function_semantics": True},
                _issuer=object(),
            ),
        )
    with pytest.raises(ClassicSemanticError, match=r"donor.*internal provenance"):
        issue_classic_donor_semantics(
            donor,
            material=_ClassicDonorSemanticMaterial(
                intervention=donor,
                donor_object=b"donor object",
                source_inputs={"source.cpp": b"int target();\n"},
                compiler_statement={"producer_node": "compiler.app.0000"},
                _issuer=object(),
            ),
            downstream_uses=(),
        )


def test_semantic_material_is_bound_to_its_exact_intervention(tmp_path: Path) -> None:
    _bundle, _graph, _overlay, donor, consumer, _clean, _effective = _base_authority(
        tmp_path, generated_carrier=False
    )
    assert donor is not None and consumer is not None
    with pytest.raises(ClassicSemanticError, match=r"candidate.*different intervention"):
        issue_classic_candidate_semantics(
            consumer.model_copy(update={"id": "function.other"}),
            material=_issued_candidate_material(
                consumer,
                seed_input=b"seed object",
                binary_inputs={f"dependency:{donor.id}": b"donor object"},
                source_inputs={},
                candidate_constraints={},
                output=b"candidate object",
                validator_trace={"same_linked_function_semantics": True},
            ),
        )
    with pytest.raises(ClassicSemanticError, match=r"donor.*different intervention"):
        issue_classic_donor_semantics(
            donor.model_copy(update={"id": "donor.other"}),
            material=_issued_donor_material(
                donor,
                donor_object=b"donor object",
                source_inputs={"source.cpp": b"int target();\n"},
                compiler_statement={"producer_node": "compiler.app.0000"},
            ),
            downstream_uses=(),
        )


def test_candidate_and_donor_proofs_bind_exact_downstream_object_lineage(
    tmp_path: Path,
) -> None:
    _bundle, _graph, _overlay, donor, consumer, _clean, _effective = _base_authority(
        tmp_path, generated_carrier=False
    )
    assert donor is not None and consumer is not None
    seed = b"seed object"
    donor_object = b"fresh private donor"
    candidate = b"candidate object"
    candidate_validation = issue_classic_candidate_semantics(
        consumer,
        material=_issued_candidate_material(
            consumer,
            seed_input=seed,
            binary_inputs={f"dependency:{donor.id}": donor_object},
            source_inputs={"seed_source": b"int target();\n"},
            candidate_constraints={"kind": consumer.family.value},
            output=candidate,
            validator_trace={"same_linked_function_semantics": True},
        ),
    )
    assert semantic_proof_matches(
        candidate_validation.proof,
        consumer.family,
        CLASSIC_SEMANTIC_CONTRACTS[consumer.family],
    )
    use = DonorSemanticUse(
        consumer.id,
        candidate_validation.proof,
        candidate_validation.input_statement,
        candidate_validation.output_statement,
        f"dependency:{donor.id}",
    )
    donor_validation = issue_classic_donor_semantics(
        donor,
        material=_issued_donor_material(
            donor,
            donor_object=donor_object,
            source_inputs={"source.cpp": b"int target();\n"},
            compiler_statement={"producer_node": "compiler.app.0000", "returncode": 0},
        ),
        downstream_uses=(use,),
    )
    assert semantic_proof_matches(
        donor_validation.proof,
        donor.family,
        CLASSIC_SEMANTIC_CONTRACTS[donor.family],
    )

    with pytest.raises(ClassicSemanticError, match="not bound to its fresh object"):
        issue_classic_donor_semantics(
            donor,
            material=_issued_donor_material(
                donor,
                donor_object=b"different donor",
                source_inputs={"source.cpp": b"int target();\n"},
                compiler_statement={
                    "producer_node": "compiler.app.0000",
                    "returncode": 0,
                },
            ),
            downstream_uses=(use,),
        )


@pytest.mark.parametrize(
    ("input_name", "constraints"),
    (
        ("target_donor_object", {"target_donor": "donor.auxiliary"}),
        ("complete_donor_object", {"complete_donor": "donor.auxiliary"}),
        ("instruction_donor_object", {"instruction_donor": "donor.auxiliary"}),
        (
            "additional_donor:donor.auxiliary",
            {"donor_variants": [{"donor": "donor.auxiliary"}]},
        ),
    ),
)
def test_named_auxiliary_donor_proofs_bind_their_exact_candidate_seat(
    input_name: str,
    constraints: dict[str, object],
) -> None:
    donor = ClassicRecipeIntervention(
        id="donor.auxiliary",
        scope=Scope(target="program", translation_unit="tu.unit"),
        rationale="private auxiliary donor compile",
        family=ClassicRecipeFamily.DECLARATION_SHAPE,
        role=ClassicRecipeRole.DONOR,
        build_target="app",
    )
    consumer = ClassicRecipeIntervention(
        id="function.target",
        scope=Scope(target="program", translation_unit="tu.unit", function="?target@@YAHXZ"),
        rationale="closed candidate using a named auxiliary donor",
        dependencies=("donor.primary",),
        family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
        role=ClassicRecipeRole.FUNCTION,
        build_target="app",
        symbol="?target@@YAHXZ",
    )
    donor_object = b"fresh auxiliary donor"
    candidate = issue_classic_candidate_semantics(
        consumer,
        material=_issued_candidate_material(
            consumer,
            seed_input=b"seed object",
            binary_inputs={
                "dependency:donor.primary": b"fresh primary donor",
                input_name: donor_object,
            },
            source_inputs={},
            candidate_constraints=constraints,
            output=b"candidate object",
            validator_trace={"same_linked_function_semantics": True},
        ),
    )
    use = DonorSemanticUse(
        consumer.id,
        candidate.proof,
        candidate.input_statement,
        candidate.output_statement,
        input_name,
    )
    validation = issue_classic_donor_semantics(
        donor,
        material=_issued_donor_material(
            donor,
            donor_object=donor_object,
            source_inputs={"source.cpp": b"int target();\n"},
            compiler_statement={"producer_node": "compiler.app.0001", "returncode": 0},
        ),
        downstream_uses=(use,),
    )
    assert validation.output_statement["downstream_uses"] == [
        {
            "kind": "typed-semantic-consumer",
            "intervention": consumer.id,
            "family": consumer.family.value,
            "input_name": input_name,
            "proof": candidate.proof.model_dump(mode="json"),
        }
    ]

    with pytest.raises(ClassicSemanticError, match="unauthorized candidate input"):
        issue_classic_donor_semantics(
            donor,
            material=_issued_donor_material(
                donor,
                donor_object=donor_object,
                source_inputs={"source.cpp": b"int target();\n"},
                compiler_statement={
                    "producer_node": "compiler.app.0001",
                    "returncode": 0,
                },
            ),
            downstream_uses=(replace(use, input_name="dependency:donor.auxiliary"),),
        )


def test_active_overlay_cannot_feed_a_linked_primary_seed(tmp_path: Path) -> None:
    bundle, graph, _overlay, donor, consumer, clean, effective = _base_authority(
        tmp_path, generated_carrier=False
    )
    assert donor is not None and consumer is not None
    snapshot = _donor_snapshot(bundle, graph, donor, consumer, clean, effective)
    active_primary = SourceInputReceipt(
        "src/unit.cpp",
        Digest.from_bytes(effective),
        len(effective),
        PrimarySourceOrigin.EFFECTIVE_OVERLAY,
    )

    with pytest.raises(ClassicSemanticError, match="not the clean manifest input"):
        prove_source_overlay_semantics(
            bundle,
            graph,
            _bound_snapshot(graph, replace(snapshot, primary_sources=(active_primary,))),
            semantic_contracts={consumer.family: _BINARY_CONTRACT},
        )


def _carrier_snapshot(
    graph: ProducerGraphDocument,
    clean: bytes,
    effective: bytes,
    *,
    ordinary_payload: bytes,
) -> OverlaySemanticSnapshot:
    carrier_receipt = EffectiveOverlayReceipt(
        "src/carrier.cpp", Digest.from_bytes(effective), len(effective)
    )
    products = (
        CompilerProduct(
            "compiler.app.0000",
            "source/src/unit.cpp",
            "build/obj/unit.obj",
            ordinary_payload,
        ),
        CompilerProduct(
            "compiler.app.0001",
            "source/src/carrier.cpp",
            "build/obj/carrier.obj",
            _coff_object("_car"),
            ("src/carrier.cpp",),
        ),
    )
    return _bound_snapshot(
        graph,
        OverlaySemanticSnapshot(
            run_binding=Digest.from_bytes(b"carrier run"),
            primary_sources=(
                SourceInputReceipt(
                    "src/carrier.cpp",
                    Digest.from_bytes(effective),
                    len(effective),
                    PrimarySourceOrigin.GENERATED_CARRIER,
                ),
                SourceInputReceipt(
                    "src/unit.cpp",
                    Digest.from_bytes(clean),
                    len(clean),
                    PrimarySourceOrigin.CLEAN_MANIFEST,
                ),
            ),
            effective_outputs=(carrier_receipt,),
            compiler_products=products,
            donor_lanes=(),
            link_closures=(
                TargetLinkClosure(
                    "program",
                    ("compiler.app.0000", "compiler.app.0001"),
                    demand_root_symbols=("_main",),
                ),
            ),
        ),
    )


def _patch_primary_comdat_selection(payload: bytes, selection: int) -> bytes:
    result = bytearray(payload)
    section_symbol = _coff_symbol_offset(payload, ".text")
    result[section_symbol + 18 + 14] = selection
    return bytes(result)


def _patch_section_comdat_flag(payload: bytes, *, present: bool) -> bytes:
    result = bytearray(payload)
    characteristics_offset = 20 + 36
    characteristics = struct.unpack_from("<I", result, characteristics_offset)[0]
    if present:
        characteristics |= 0x00001000
    else:
        characteristics &= ~0x00001000
    struct.pack_into("<I", result, characteristics_offset, characteristics)
    return bytes(result)


def _patch_reference_as_object_local(payload: bytes, name: str) -> bytes:
    result = bytearray(payload)
    offset = _coff_symbol_offset(payload, name)
    struct.pack_into("<h", result, offset + 12, 1)
    result[offset + 16] = 3
    return bytes(result)


def _direct_carrier_trace(
    bundle: ProjectBundle,
    *,
    ordinary_payload: bytes | None = None,
    carrier_payload: bytes | None = None,
    linker_inputs: tuple[str, ...] | None = None,
    linker_arguments: tuple[str, ...] | None = None,
    archives: tuple[ArchiveInput, ...] = (),
    canonical_identity: bool = True,
    carrier_generator_kinds: tuple[str, ...] = ("fixture",),
) -> dict[str, object]:
    ordinary_payload = ordinary_payload or _coff_object("_shared", body_payload=b"\x90\xc3")
    carrier_payload = carrier_payload or _coff_object("_shared", body_payload=b"\xc3")
    products = {
        "compiler.app.0000": CompilerProduct(
            "compiler.app.0000",
            "source/src/unit.cpp",
            "build/obj/unit.obj",
            ordinary_payload,
        ),
        "compiler.app.0001": CompilerProduct(
            "compiler.app.0001",
            "source/src/carrier.cpp",
            "build/obj/carrier.obj",
            carrier_payload,
            ("src/carrier.cpp",),
        ),
    }
    compiler_node_ids = tuple(sorted(products, key=str.casefold))
    archive_refs = tuple(sorted((item.archive_ref for item in archives), key=str.casefold))
    identity = issue_msvc420_linker_identity(bundle.toolchain_lock)
    assert identity is not None
    return _carrier_isolation_trace(
        target=TargetLinkClosure(
            "program",
            compiler_node_ids,
            archive_refs,
            archives,
        ),
        linker_arguments=(
            linker_arguments if linker_arguments is not None else ("/INCREMENTAL:NO", "/OPT:REF")
        ),
        linker_inputs=(
            linker_inputs
            if linker_inputs is not None
            else ("build/obj/unit.obj", "build/obj/carrier.obj")
        ),
        linker_identity=identity if canonical_identity else None,
        products=products,
        carrier_node_ids=frozenset({"compiler.app.0001"}),
        carrier_generator_kinds={"compiler.app.0001": carrier_generator_kinds},
    )


def test_const_pool_carrier_seals_one_intentional_anonymous_rdata(tmp_path: Path) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)

    trace = _direct_carrier_trace(
        bundle,
        ordinary_payload=_coff_object("_main"),
        carrier_payload=_coff_const_pool(),
        carrier_generator_kinds=("const_pool",),
    )

    sections = trace["intentional_const_pool_sections"]
    assert sections == [
        {
            "object": "build/obj/carrier.obj",
            "section": 1,
            "name": ".rdata",
            "size": 20,
            "digest": Digest.from_bytes(bytes(range(20))).value,
        }
    ]


@pytest.mark.parametrize(
    ("payload", "generator_kinds", "message"),
    (
        (_coff_const_pool(), ("fixture",), "unclassified non-COMDAT"),
        (_coff_const_pool(relocation=True), ("const_pool",), "unclassified non-COMDAT"),
        (
            _coff_const_pool(external_owner=True),
            ("const_pool",),
            "unexpectedly defines an external symbol",
        ),
    ),
)
def test_const_pool_carrier_has_no_generic_data_admission(
    payload: bytes,
    generator_kinds: tuple[str, ...],
    message: str,
    tmp_path: Path,
) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)

    with pytest.raises(ClassicSemanticError, match=message):
        _direct_carrier_trace(
            bundle,
            ordinary_payload=_coff_object("_main"),
            carrier_payload=payload,
            carrier_generator_kinds=generator_kinds,
        )


def test_link420_order_shadows_a_divergent_carrier_comdat(tmp_path: Path) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)

    trace = _direct_carrier_trace(bundle)

    receipts = trace["ordered_discarded_select_any_comdats"]
    assert isinstance(receipts, list) and len(receipts) == 1
    assert receipts[0]["winner"]["linker_input_ordinal"] == 0
    assert receipts[0]["discarded_carriers"][0]["linker_input_ordinal"] == 1
    assert trace["linker_controls"] == {
        "dead_comdat_elimination": "/OPT:REF",
        "incremental_state": "/INCREMENTAL:NO",
    }


def test_order_shadow_discards_the_complete_associative_chain(tmp_path: Path) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)

    trace = _direct_carrier_trace(
        bundle,
        carrier_payload=_coff_object_with_associative_chain("_shared"),
    )

    receipt = trace["ordered_discarded_select_any_comdats"][0]
    children = receipt["discarded_carriers"][0]["associative_sections"]
    assert [item["section"] for item in children] == [2, 3]


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"cycle": True}, "cyclic COMDAT chain"),
        ({"orphan": True}, "orphaned associative COMDAT"),
    ),
)
def test_order_shadow_refuses_malformed_associative_chains(
    changes: dict[str, bool], message: str, tmp_path: Path
) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)

    with pytest.raises(ClassicSemanticError, match=message):
        _direct_carrier_trace(
            bundle,
            carrier_payload=_coff_object_with_associative_chain("_shared", **changes),
        )


def test_carrier_first_duplicate_is_not_order_shadowed(tmp_path: Path) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)

    with pytest.raises(ClassicSemanticError, match="not shadowed"):
        _direct_carrier_trace(
            bundle,
            linker_inputs=("build/obj/carrier.obj", "build/obj/unit.obj"),
        )


def test_archive_only_duplicate_provider_is_not_a_direct_winner(tmp_path: Path) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)
    archive_ref = "system-library/ordinary.lib"
    archive = ArchiveInput(
        archive_ref,
        _coff_archive("ordinary.obj", _coff_object("_shared", body_payload=b"\x90\xc3")),
    )

    with pytest.raises(ClassicSemanticError, match="direct ordinary provider"):
        _direct_carrier_trace(
            bundle,
            ordinary_payload=_coff_object("_ord"),
            linker_inputs=(archive_ref, "build/obj/carrier.obj"),
            archives=(archive,),
        )


def test_unrelated_archive_before_direct_winner_does_not_overconstrain_order(
    tmp_path: Path,
) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)
    archive_ref = "system-library/early.lib"
    archive = ArchiveInput(
        archive_ref,
        _coff_archive("other.obj", _coff_object("_other")),
    )

    trace = _direct_carrier_trace(
        bundle,
        linker_inputs=(archive_ref, "build/obj/unit.obj", "build/obj/carrier.obj"),
        archives=(archive,),
    )

    assert len(trace["ordered_discarded_select_any_comdats"]) == 1


def test_duplicate_archive_before_direct_winner_is_refused(tmp_path: Path) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)
    archive_ref = "system-library/early.lib"
    archive = ArchiveInput(
        archive_ref,
        _coff_archive("earlier.obj", _coff_object("_shared", body_payload=b"\x90\x90\xc3")),
    )

    with pytest.raises(ClassicSemanticError, match="not shadowed"):
        _direct_carrier_trace(
            bundle,
            linker_inputs=(archive_ref, "build/obj/unit.obj", "build/obj/carrier.obj"),
            archives=(archive,),
        )


def test_duplicate_archive_after_direct_winner_is_also_shadowed(tmp_path: Path) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)
    archive_ref = "system-library/later.lib"
    archive = ArchiveInput(
        archive_ref,
        _coff_archive("later.obj", _coff_object("_shared", body_payload=b"\x90\x90\xc3")),
    )

    trace = _direct_carrier_trace(
        bundle,
        linker_inputs=("build/obj/unit.obj", archive_ref, "build/obj/carrier.obj"),
        archives=(archive,),
    )

    receipts = trace["ordered_discarded_select_any_comdats"]
    assert receipts[0]["later_archive_providers"][0]["linker_input_ordinals"] == [1]


def test_archive_cannot_hide_an_exact_generated_carrier_clone(tmp_path: Path) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)
    carrier = _coff_object("_shared", body_payload=b"\xc3")
    archive_ref = "system-library/clone.lib"
    archive = ArchiveInput(archive_ref, _coff_archive("clone.obj", carrier))

    with pytest.raises(ClassicSemanticError, match="generated-carrier object clone"):
        _direct_carrier_trace(
            bundle,
            carrier_payload=carrier,
            linker_inputs=(
                "build/obj/unit.obj",
                archive_ref,
                "build/obj/carrier.obj",
            ),
            archives=(archive,),
        )


@pytest.mark.parametrize(
    "directive",
    (b"/merge:.text=.data", b"/disallowlib:runtime.lib"),
)
def test_carrier_cannot_change_global_linker_controls(directive: bytes, tmp_path: Path) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)

    with pytest.raises(ClassicSemanticError, match="global linker control"):
        _direct_carrier_trace(
            bundle,
            carrier_payload=_coff_object(
                "_shared", section_name=".drectve", body_payload=directive
            ),
        )


@pytest.mark.parametrize(
    "selection",
    (1, 3, 4, 5, 6),
)
def test_duplicate_carrier_requires_select_any(selection: int, tmp_path: Path) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)
    carrier = _patch_primary_comdat_selection(_coff_object("_shared"), selection)

    with pytest.raises(ClassicSemanticError, match="COMDAT"):
        _direct_carrier_trace(bundle, carrier_payload=carrier)


def test_duplicate_carrier_requires_the_comdat_section_flag(tmp_path: Path) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)
    carrier = _patch_section_comdat_flag(_coff_object("_shared"), present=False)

    with pytest.raises(ClassicSemanticError, match="COMDAT"):
        _direct_carrier_trace(bundle, carrier_payload=carrier)


def test_duplicate_carrier_requires_an_exact_owner_at_offset_zero(tmp_path: Path) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)
    carrier = _patch_coff_symbol(_coff_object("_shared"), "_shared", value=1)

    with pytest.raises(ClassicSemanticError, match="primary COMDAT"):
        _direct_carrier_trace(bundle, carrier_payload=carrier)


def test_duplicate_carrier_rejects_object_local_relocations(tmp_path: Path) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)
    carrier = _patch_reference_as_object_local(
        _coff_object("_shared", reference="_local"), "_local"
    )

    with pytest.raises(ClassicSemanticError, match="object-local relocation"):
        _direct_carrier_trace(bundle, carrier_payload=carrier)


def test_duplicate_carrier_must_be_one_direct_input(tmp_path: Path) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)

    with pytest.raises(ClassicSemanticError, match="one unique direct linker input"):
        _direct_carrier_trace(
            bundle,
            linker_inputs=(
                "build/obj/unit.obj",
                "build/obj/carrier.obj",
                "build/obj/carrier.obj",
            ),
        )


@pytest.mark.parametrize(
    "arguments",
    (
        ("/INCREMENTAL:NO",),
        ("/INCREMENTAL:NO", "/OPT:NOREF"),
        ("/INCREMENTAL:NO", "/OPT:REF,ICF"),
        ("/INCREMENTAL", "/OPT:REF"),
        ("/INCREMENTAL:NO", "/OPT:REF", "/FORCE:MULTIPLE"),
    ),
)
def test_carrier_theorem_requires_explicit_safe_link_controls(
    arguments: tuple[str, ...], tmp_path: Path
) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)

    with pytest.raises(ClassicSemanticError, match="generated-carrier isolation"):
        _direct_carrier_trace(bundle, linker_arguments=arguments)


def test_carrier_theorem_requires_the_exact_link420_identity(tmp_path: Path) -> None:
    bundle, *_ = _base_authority(tmp_path, generated_carrier=True)

    with pytest.raises(ClassicSemanticError, match=r"canonical LINK 4\.20 identity"):
        _direct_carrier_trace(bundle, canonical_identity=False)


def test_unreferenced_generated_carrier_has_a_positive_isolation_proof(
    tmp_path: Path,
) -> None:
    bundle, graph, overlay, _donor, _consumer, clean, effective = _base_authority(
        tmp_path, generated_carrier=True
    )
    snapshot = _carrier_snapshot(graph, clean, effective, ordinary_payload=_coff_object("_main"))

    result = prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})

    carrier_trace = result.trace[overlay.id]["carrier_isolation"]  # type: ignore[index]
    assert carrier_trace["unique_unreferenced_definitions"] == ["_car"]  # type: ignore[index]


def test_generated_header_is_visible_only_in_the_carrier_compile_epoch(
    tmp_path: Path,
) -> None:
    bundle, graph, overlay, _donor, _consumer, clean, effective = _base_authority(
        tmp_path, generated_carrier=True
    )
    header_path = "src/generated.h"
    header = b"struct EntropyHeader {};\n"
    values = {item.name: item.value for item in overlay.parameters}
    values["outputs"] = [
        *values["outputs"],  # type: ignore[misc]
        {
            "path": header_path,
            "effective": Digest.from_bytes(header).value,
            "size": len(header),
            "ops": [{"op": "append", "gen": {"k": "record_header"}}],
        },
    ]
    overlay = overlay.model_copy(
        update={
            "parameters": tuple(
                ClassicField(name=name, value=value) for name, value in sorted(values.items())
            )
        }
    )
    document = bundle.intervention_documents[0].model_copy(update={"interventions": (overlay,)})
    bundle = bundle.model_copy(update={"intervention_documents": (document,)})
    snapshot = _carrier_snapshot(graph, clean, effective, ordinary_payload=_coff_object("_main"))
    carrier_product = replace(
        snapshot.compiler_products[1],
        generated_inputs=("src/carrier.cpp", header_path),
    )
    snapshot = _bound_snapshot(
        graph,
        replace(
            snapshot,
            primary_sources=(
                *snapshot.primary_sources,
                SourceInputReceipt(
                    header_path,
                    Digest.from_bytes(header),
                    len(header),
                    PrimarySourceOrigin.GENERATED_CARRIER,
                ),
            ),
            effective_outputs=(
                *snapshot.effective_outputs,
                EffectiveOverlayReceipt(header_path, Digest.from_bytes(header), len(header)),
            ),
            compiler_products=(snapshot.compiler_products[0], carrier_product),
        ),
    )

    result = prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})
    assert result.proofs[overlay.id].family == ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH

    ordinary_product = replace(snapshot.compiler_products[0], generated_inputs=(header_path,))
    with pytest.raises(ClassicSemanticError, match=r"ordinary compiler.*epoch"):
        prove_source_overlay_semantics(
            bundle,
            graph,
            _bound_snapshot(
                graph,
                replace(
                    snapshot,
                    compiler_products=(ordinary_product, carrier_product),
                ),
            ),
            semantic_contracts={},
        )


def test_complete_raw_archive_expansion_recognizes_import_objects(
    tmp_path: Path,
) -> None:
    bundle, graph, overlay, _donor, _consumer, clean, effective = _base_authority(
        tmp_path, generated_carrier=True
    )
    archive_ref = "system-library/runtime.lib"
    nodes = tuple(
        node.model_copy(
            update={
                "inputs": (*node.inputs, archive_ref),
                "arguments": (*node.arguments, "runtime.lib"),
            }
        )
        if node.role is ProducerRole.LINKER
        else node
        for node in graph.nodes
    )
    graph = graph.model_copy(update={"nodes": nodes})
    archive = _coff_archive("runtime.obj", _import_object("_puts", "msvcrt.dll"))
    snapshot = _carrier_snapshot(graph, clean, effective, ordinary_payload=_coff_object("_main"))
    closure = replace(
        snapshot.link_closures[0],
        archive_refs=(archive_ref,),
        archives=(ArchiveInput(archive_ref, archive),),
    )

    result = prove_source_overlay_semantics(
        bundle,
        graph,
        _bound_snapshot(graph, replace(snapshot, link_closures=(closure,))),
        semantic_contracts={},
    )

    carrier_trace = result.trace[overlay.id]["carrier_isolation"]  # type: ignore[index]
    assert carrier_trace["import_object_count"] == 1  # type: ignore[index]


def test_archive_member_omission_cannot_be_claimed_as_complete(tmp_path: Path) -> None:
    bundle, graph, _overlay, _donor, _consumer, clean, effective = _base_authority(
        tmp_path, generated_carrier=True
    )
    archive_ref = "system-library/runtime.lib"
    nodes = tuple(
        node.model_copy(update={"inputs": (*node.inputs, archive_ref)})
        if node.role is ProducerRole.LINKER
        else node
        for node in graph.nodes
    )
    graph = graph.model_copy(update={"nodes": nodes})
    snapshot = _carrier_snapshot(graph, clean, effective, ordinary_payload=_coff_object("_main"))
    closure = replace(snapshot.link_closures[0], archive_refs=(archive_ref,))

    with pytest.raises(ClassicSemanticError, match="raw archive closure differs"):
        prove_source_overlay_semantics(
            bundle,
            graph,
            _bound_snapshot(graph, replace(snapshot, link_closures=(closure,))),
            semantic_contracts={},
        )


def test_inbound_reference_to_generated_carrier_fails_closed(tmp_path: Path) -> None:
    bundle, graph, _overlay, _donor, _consumer, clean, effective = _base_authority(
        tmp_path, generated_carrier=True
    )
    snapshot = _carrier_snapshot(
        graph,
        clean,
        effective,
        ordinary_payload=_coff_object("_main", reference="_car"),
    )

    with pytest.raises(ClassicSemanticError, match="inbound carrier references"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


def test_hidden_include_directive_cannot_root_a_generated_carrier(
    tmp_path: Path,
) -> None:
    bundle, graph, _overlay, _donor, _consumer, clean, effective = _base_authority(
        tmp_path, generated_carrier=True
    )
    snapshot = _carrier_snapshot(
        graph,
        clean,
        effective,
        ordinary_payload=_coff_object(
            "_main",
            section_name=".drectve",
            body_payload=b"/include:_car ",
        ),
    )

    with pytest.raises(ClassicSemanticError, match="roots a carrier definition"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})
