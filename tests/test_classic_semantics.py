from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from reprobit.classic.source_proofs import source_overlay_tokens
from reprobit.classic_includes import IncludeOrigin
from reprobit.classic_project import ClassicProjectError
from reprobit.classic_resources import (
    ResourceDependencyReceipt,
    ResourceRead,
    ResourceReadKind,
)
from reprobit.classic_runtime import _project_overlay_resource_reader_closure
from reprobit.classic_semantics import (
    CLASSIC_SEMANTIC_CONTRACTS,
    SOURCE_OVERLAY_OBLIGATIONS,
    SOURCE_OVERLAY_VALIDATOR_DIGEST,
    SOURCE_OVERLAY_VALIDATOR_ID,
    ArchiveInput,
    ClassicSemanticError,
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
    _compiler_has_define,
    _DeclarationFact,
    _macro_capture_collisions,
    _payload_preprocessor_mutations,
    _portable_tree_statement,
    _require_no_compiler_macro_capture,
    _validate_compiler_invocation,
    _validate_compiler_namespaces,
    _validate_declaration_odr,
    classic_candidate_input_statement,
    classic_compiler_path_profile_digest,
    classic_link_relevant_coff_projection,
    compiler_epoch_invocation_digest,
    compiler_namespace_evidence_digest,
    issue_classic_candidate_semantics,
    issue_classic_donor_semantics,
    issue_semantic_proof,
    overlay_semantic_run_binding,
    parse_classic_archive_member_directives,
    parse_classic_coff_directives,
    parse_classic_import_object,
    plan_project_overlay_compiler_epochs,
    prove_classic_coff_line_number_correspondence,
    prove_source_overlay_semantics,
    semantic_proof_matches,
    validate_project_overlay_compiler_epoch,
)
from reprobit.model import Digest, Scope
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerNode,
    ProducerRole,
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

    monkeypatch.setattr("reprobit.classic_semantics.iter_source_overlay_tokens", tokens)
    cache: dict[tuple[Digest, int], frozenset[tuple[str, str]]] = {}

    first = _payload_preprocessor_mutations(
        (payload,), prevalidated_digests=(digest,), cache=cache
    )
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
            if identifier.isascii() and (
                identifier[:1].isalpha() or identifier.startswith("_")
            ) and all(character.isalnum() or character == "_" for character in identifier):
                expected.add((tokens[index + 1], identifier))

    assert _payload_preprocessor_mutations((payload,)) == frozenset(expected)


def test_preprocessor_candidate_filter_skips_noncandidate_binary_lexing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "reprobit.classic_semantics.iter_source_overlay_tokens",
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
    "define_arguments",
    (
        ("/DCaptured#1",),
        ("/D", "Captured#1"),
        ("-DCaptured#1",),
        ("-D", "Captured#1"),
    ),
)
def test_compiler_define_recognizes_hash_value_separator(
    define_arguments: tuple[str, ...],
) -> None:
    node = ProducerNode(
        id="compiler.app.hash-define",
        role=ProducerRole.COMPILER,
        owner="app",
        arguments=(*define_arguments, "/c", "${SOURCE}/src/unit.cpp"),
        inputs=("source/src/unit.cpp",),
        outputs=("build/obj/unit.obj",),
    )

    assert _compiler_has_define(node, "Captured")


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
    section: int,
    symbol_type: int,
    storage: int,
    auxiliary_count: int = 0,
) -> bytes:
    encoded = name.encode("ascii")
    assert len(encoded) <= 8
    return encoded.ljust(8, b"\0") + struct.pack(
        "<IhHBB", 0, section, symbol_type, storage, auxiliary_count
    )


def _coff_object(
    definition: str,
    *,
    reference: str | None = None,
    section_name: str = ".text",
    body_payload: bytes | None = None,
    relocation_offset_in_section: int = 0,
    relocation_type: int = 6,
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
    relocation_offset = section_table_end + len(body) if reference is not None else 0
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
        struct.pack("<IHHIhBBH", len(body), 1 if reference else 0, 0, 0, 0, 2, 0, 0),
        _symbol(definition, section=1, symbol_type=32, storage=2),
    ]
    if reference is not None:
        target_index = 3
        symbols.append(_symbol(reference, section=0, symbol_type=0, storage=2))
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
        1 if reference else 0,
        0,
        0x60501020,
    )
    return header + section + body + relocation + symbol_table + struct.pack("<I", 4)


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


def _add_coff_line_table(
    payload: bytes, records: tuple[tuple[int, int], ...]
) -> bytes:
    """Insert structurally valid ``(value, line)`` records in section one."""

    assert records
    symbol_offset = struct.unpack_from("<I", payload, 8)[0]
    encoded = b"".join(struct.pack("<IH", value, line) for value, line in records)
    result = bytearray(payload[:symbol_offset] + encoded + payload[symbol_offset:])
    struct.pack_into("<I", result, 8, symbol_offset + len(encoded))
    struct.pack_into("<I", result, 48, symbol_offset)
    struct.pack_into("<H", result, 54, len(records))
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
        _add_coff_line_record(
            _coff_object("_debug", section_name=".debug$S", body_payload=b"one")
        ),
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

    baseline = classic_link_relevant_coff_projection(
        baseline_payload, label="baseline.obj"
    )
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
    toolchain = ToolchainLock(
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
    paths = LogicalPathProfile(source="Z:\\src", build="Z:\\build", toolchain="Z:\\toolchain")
    spec = ProjectSpec(
        schema_version=3,
        project_id="semantic-fixture",
        build=ProducerGraphBuildAdapter(),
        toolchain=ToolchainRef(profile="msvc-42"),
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
            mode="semantic-fixture",
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
            phase=None,
            translation_units=(unit_plan,) if unit_plan is not None else (),
            source_overlay_digest=Digest.from_bytes(
                canonical_json(overlay.model_dump(mode="json"))
            ),
            source_overlay_interventions=(overlay.id,),
            archives=(),
            terminal_producers={},
            execution_backends={},
            toolchain_policy={},
            target_policies=[],
            target_gates=(
                ClassicTargetGate(
                    target_id="program",
                    build_target="app",
                    completion={},
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
        schema_version=1,
        source_manifest_digest=source_manifest_digest(manifest),
        toolchain_lock_digest=toolchain_document_digest(toolchain),
        path_profile_id=paths.id,
        extractor="cmake-unix-makefiles-v1",
        nodes=(
            *compiler_nodes,
            ProducerNode(
                id="linker.app.0002",
                role=ProducerRole.LINKER,
                owner="app",
                target_id="program",
                arguments=(
                    "/out:${BUILD}/out/program.exe",
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
    semantic_proof = issue_semantic_proof(
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
                TargetLinkClosure("program", ("compiler.app.0000",), root_symbols=("_main",)),
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
    graph = graph.model_copy(update={"source_manifest_digest": source_manifest_digest(manifest)})
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
            TargetLinkClosure("program", ("compiler.app.0000",), root_symbols=("_main",)),
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
        b"#ifndef FRESH_GUARD\n"
        b"#define FRESH_GUARD\n"
        b"enum FreshRecord {\n"
        b"\tFreshValue\n"
        b"};\n"
        b"#endif\n"
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

    with pytest.raises(ClassicSemanticError, match="changes runtime state"):
        prove_source_overlay_semantics(bundle, graph, snapshot, semantic_contracts={})


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
        source_manifest_digest=source_manifest_digest(manifest),
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
        b"int prefix;\r" b'#include "unit.cpp"\r',
        b"int prefix;\r\n" b'#include "unit.cpp"\r\n',
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
        secondary_reader_payloads={
            "toolchain/include/hostile.h": b'#include "unit.cpp"\n'
        },
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
    assert plan.reader_closure_fallbacks == (
        "toolchain-include-namespace-unavailable",
    )


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
        source_manifest_digest=graph.source_manifest_digest,
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
    assert plan.declaration_outputs == {"src/unit.cpp": b"int main() {\n\treturn 0;\n}\n"}


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
    graph = graph.model_copy(update={"source_manifest_digest": source_manifest_digest(manifest)})

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


def test_registry_covers_every_nonlegacy_closed_classic_family() -> None:
    assert set(CLASSIC_SEMANTIC_CONTRACTS) == set(ClassicRecipeFamily) - {
        ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION,
        ClassicRecipeFamily.ARCHIVE_ADMISSION,
    }


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
        seed_input=seed,
        binary_inputs={f"dependency:{donor.id}": donor_object},
        source_inputs={"seed_source": b"int target();\n"},
        candidate_constraints={"kind": consumer.family.value},
        output=candidate,
        validator_trace={"same_linked_function_semantics": True},
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
        donor_object=donor_object,
        source_inputs={"source.cpp": b"int target();\n"},
        compiler_statement={"producer_node": "compiler.app.0000", "returncode": 0},
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
            donor_object=b"different donor",
            source_inputs={"source.cpp": b"int target();\n"},
            compiler_statement={"producer_node": "compiler.app.0000", "returncode": 0},
            downstream_uses=(use,),
        )


@pytest.mark.parametrize(
    ("input_name", "constraints"),
    (
        ("target_donor_object", {"target_donor": "d_auxiliary"}),
        ("complete_donor_object", {"complete_donor": "d_auxiliary"}),
        ("instruction_donor_object", {"instruction_donor": "d_auxiliary"}),
        (
            "additional_donor:d_auxiliary",
            {"donor_variants": [{"donor": "d_auxiliary"}]},
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
        parameters=(ClassicField(name="legacy_recipe_id", value="d_auxiliary"),),
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
        seed_input=b"seed object",
        binary_inputs={
            "dependency:donor.primary": b"fresh primary donor",
            input_name: donor_object,
        },
        source_inputs={},
        candidate_constraints=constraints,
        output=b"candidate object",
        validator_trace={"same_linked_function_semantics": True},
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
        donor_object=donor_object,
        source_inputs={"source.cpp": b"int target();\n"},
        compiler_statement={"producer_node": "compiler.app.0001", "returncode": 0},
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
            donor_object=donor_object,
            source_inputs={"source.cpp": b"int target();\n"},
            compiler_statement={
                "producer_node": "compiler.app.0001",
                "returncode": 0,
            },
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
                    root_symbols=("_main",),
                ),
            ),
        ),
    )


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
