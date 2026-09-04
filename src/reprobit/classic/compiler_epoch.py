"""Compiler-epoch namespace validation and counterfactual COFF auditing."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Literal, cast

from reprobit.classic.coff_evidence import (
    _coff_directive_receipt,
    _CoffObject,
    _CoffSymbol,
    _external_definitions,
    _parse_coff,
)
from reprobit.classic.coff_projection import (
    _coff_compiler_congruence_trace,
    _CrtPullLinkerDependency,
    _OrderedArchiveSeedDependency,
)
from reprobit.classic.coff_projection_code import _runtime_projection_equivalence_proof
from reprobit.classic.coff_projection_runtime import (
    _external_function_owner,
    _RuntimeProjectionEquivalence,
)
from reprobit.classic.coff_projection_statements import _CODE_SECTION_PREFIXES
from reprobit.classic.compiler_identity import issue_msvc420_compiler_identity
from reprobit.classic.compiler_state_foundation import CompilerStateCompilerEvidence
from reprobit.classic.semantic_contracts import (
    CleanSourceInput,
    CompilerEpochInvocation,
    CompilerInputEvidenceKind,
    CompilerNamespaceEvidence,
    CompilerProduct,
    CompilerSourceRead,
    ProjectOverlayCounterfactualAudit,
    ProjectOverlaySourcePair,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.classic.source_overlay import (
    _compiler_shape,
    _derive_project_overlay_compiler_epoch,
    _OverlaySourceValidation,
    _toolchain_include_roots,
    _unique,
)
from reprobit.classic.source_overlay_claims import (
    _ORDERED_ARCHIVE_SEED_HELPER,
    _ORDERED_ARCHIVE_SEED_POLICY,
    _payload_preprocessor_mutations,
    _relative,
    _require_no_compiler_macro_capture,
    _token_texts,
)
from reprobit.model import Digest
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerNode,
    ProducerRole,
)
from reprobit.schema import ProjectBundle
from reprobit.strict_json import canonical_json


def _helper_delta_sections(
    *,
    clean: _CoffObject,
    effective: _CoffObject,
    helper_identifiers: Sequence[str],
) -> tuple[frozenset[int], frozenset[str]]:
    clean_definitions = _external_definitions(clean)
    effective_definitions = _external_definitions(effective)
    extra_names = frozenset(set(effective_definitions) - set(clean_definitions))
    if not extra_names:
        raise ClassicSemanticError(
            f"helper source {effective.label!r} introduces no external definition"
        )
    for identifier in helper_identifiers:
        if not any(identifier in name for name in extra_names):
            raise ClassicSemanticError(
                f"helper {identifier!r} has no independently derived COFF definition"
            )
    clean_names = set(clean_definitions)
    by_section: dict[int, set[str]] = defaultdict(set)
    for name, section in effective_definitions.items():
        by_section[section.number].add(name)
    excluded = {effective_definitions[name].number for name in extra_names}
    if any(by_section[number] & clean_names for number in excluded):
        raise ClassicSemanticError(
            f"helper source {effective.label!r} shares a section with baseline definitions"
        )

    changed = True
    while changed:
        changed = False
        inbound: dict[int, set[int]] = defaultdict(set)
        for source in effective.sections:
            if source.name.casefold().startswith(".debug"):
                continue
            for relocation in source.relocations:
                if relocation.target_section > 0:
                    inbound[relocation.target_section].add(source.number)
        for section in effective.sections:
            if section.number in excluded or section.name.casefold().startswith(".debug"):
                continue
            associated = section.comdat_associated
            referenced_only_by_helpers = bool(inbound.get(section.number)) and inbound[
                section.number
            ].issubset(excluded)
            if associated in excluded or (
                referenced_only_by_helpers and not (by_section[section.number] & clean_names)
            ):
                excluded.add(section.number)
                changed = True
    return frozenset(excluded), extra_names


def _crt_pull_linker_dependencies(
    *,
    clean: _CoffObject,
    effective: _CoffObject,
    excluded_sections: frozenset[int],
    helper_identifiers: Sequence[str],
) -> tuple[_CrtPullLinkerDependency, ...]:
    """Derive only the novel undefined calls emitted by typed ``crt_pull`` helpers."""

    if not helper_identifiers:
        return ()
    definitions = _external_definitions(effective)
    pull_sections: set[int] = set()
    helper_sections: dict[str, int] = {}
    for identifier in helper_identifiers:
        matches = [
            (name, section.number)
            for name, section in definitions.items()
            if identifier in name and section.number in excluded_sections
        ]
        if len(matches) != 1:
            raise ClassicSemanticError(
                f"crt_pull helper {identifier!r} has {len(matches)} unique COFF definitions"
            )
        name, section_number = matches[0]
        section = effective.sections[section_number - 1]
        if (
            not section.name.casefold().startswith(_CODE_SECTION_PREFIXES)
            or _external_function_owner(effective, section) != name
        ):
            raise ClassicSemanticError(
                f"crt_pull helper {identifier!r} lacks one private code-function section"
            )
        helper_sections[identifier] = section_number
        pull_sections.add(section_number)

    clean_names = {symbol.name for symbol in clean.symbols}
    candidate_sites: dict[str, list[tuple[int, int, int, str]]] = defaultdict(list)
    helpers_with_pull: set[str] = set()
    for identifier, section_number in helper_sections.items():
        section = effective.sections[section_number - 1]
        for relocation in section.relocations:
            if relocation.target in clean_names or relocation.target_section != 0:
                continue
            if (
                relocation.target_storage != 2
                or relocation.target_value != 0
                or relocation.target_type != 0x20
                or relocation.relocation_type != 0x14
                or any(relocation.addend)
            ):
                raise ClassicSemanticError(
                    f"crt_pull helper {identifier!r} adds a non-call linker dependency "
                    f"{relocation.target!r}"
                )
            helpers_with_pull.add(identifier)
            candidate_sites[relocation.target].append(
                (
                    section_number,
                    relocation.offset,
                    relocation.relocation_type,
                    relocation.addend.hex(),
                )
            )
    missing = sorted(set(helper_identifiers) - helpers_with_pull)
    if missing:
        raise ClassicSemanticError(
            f"crt_pull helpers introduce no novel archive dependency: {missing}"
        )

    clean_directives = _coff_directive_receipt(clean)
    directives = _coff_directive_receipt(effective)
    rooted = (set(directives.include_symbols) - set(clean_directives.include_symbols)) | (
        set(directives.export_symbols) - set(clean_directives.export_symbols)
    )
    result: list[_CrtPullLinkerDependency] = []
    for name, sites in sorted(candidate_sites.items(), key=lambda item: item[0]):
        rows = [symbol for symbol in effective.symbols if symbol.name == name]
        if (
            len(rows) != 1
            or rows[0].storage != 2
            or rows[0].section != 0
            or rows[0].value != 0
            or rows[0].symbol_type != 0x20
            or rows[0].auxiliary_count != 0
        ):
            raise ClassicSemanticError(
                f"crt_pull linker dependency {name!r} lacks one exact undefined function row"
            )
        if name in rooted:
            raise ClassicSemanticError(
                f"crt_pull linker dependency {name!r} is also a rooted linker control"
            )
        foreign_sections = sorted(
            {
                section.number
                for section in effective.sections
                if not section.name.casefold().startswith(".debug")
                for relocation in section.relocations
                if relocation.target == name and section.number not in pull_sections
            }
        )
        if foreign_sections:
            raise ClassicSemanticError(
                f"crt_pull linker dependency {name!r} is referenced outside its helpers: "
                f"{foreign_sections}"
            )
        result.append(
            _CrtPullLinkerDependency(
                name=name,
                symbol_type=rows[0].symbol_type,
                helper_sections=tuple(sorted({site[0] for site in sites})),
                relocation_sites=tuple(sorted(sites)),
            )
        )
    return tuple(result)


def _seed_order_dependencies(
    *,
    clean: _CoffObject,
    effective: _CoffObject,
    excluded_sections: frozenset[int],
    seed_helpers: Sequence[tuple[str, str]],
) -> tuple[_OrderedArchiveSeedDependency, ...]:
    """Derive the exact MSVC 4.20 linker dependencies owned by ``SeedOrder``."""

    if not seed_helpers:
        return ()
    if tuple(seed_helpers) != ((_ORDERED_ARCHIVE_SEED_HELPER, _ORDERED_ARCHIVE_SEED_POLICY),):
        raise ClassicSemanticError("ordered archive seed helper declaration differs")

    helper_identifier, policy = seed_helpers[0]
    definitions = _external_definitions(effective)
    matches = [
        (name, section.number)
        for name, section in definitions.items()
        if helper_identifier in name and section.number in excluded_sections
    ]
    if len(matches) != 1:
        raise ClassicSemanticError(
            f"ordered archive seed helper {helper_identifier!r} has "
            f"{len(matches)} unique COFF definitions"
        )
    helper_symbol, helper_section = matches[0]
    section = effective.sections[helper_section - 1]
    if (
        not section.name.casefold().startswith(_CODE_SECTION_PREFIXES)
        or _external_function_owner(effective, section) != helper_symbol
    ):
        raise ClassicSemanticError(
            f"ordered archive seed helper {helper_identifier!r} lacks one private "
            "code-function section"
        )

    clean_names = {symbol.name for symbol in clean.symbols}
    candidate_sites: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
    binding_kinds: dict[str, Literal["function-rel32", "data-dir32"]] = {}
    for relocation in section.relocations:
        if relocation.target_section != 0 or relocation.target in clean_names:
            continue
        site = (relocation.offset, relocation.relocation_type, relocation.addend.hex())
        binding_kind: Literal["function-rel32", "data-dir32"]
        if (
            relocation.target_storage == 2
            and relocation.target_value == 0
            and relocation.target_type == 0x20
            and relocation.relocation_type == 0x14
            and not any(relocation.addend)
        ):
            binding_kind = "function-rel32"
        elif (
            relocation.target_storage == 2
            and relocation.target_value == 0
            and relocation.target_type == 0
            and relocation.relocation_type == 0x06
            and not any(relocation.addend)
        ):
            binding_kind = "data-dir32"
        else:
            raise ClassicSemanticError(
                f"ordered archive seed helper {helper_identifier!r} adds a non-call "
                f"or inexact data linker dependency {relocation.target!r}"
            )
        previous_kind = binding_kinds.setdefault(relocation.target, binding_kind)
        if previous_kind != binding_kind:
            raise ClassicSemanticError(
                f"ordered archive seed dependency {relocation.target!r} has mixed binding kinds"
            )
        candidate_sites[relocation.target].append(site)
    if not candidate_sites:
        raise ClassicSemanticError(
            f"ordered archive seed helper {helper_identifier!r} introduces no novel "
            "archive dependency"
        )

    clean_directives = _coff_directive_receipt(clean)
    directives = _coff_directive_receipt(effective)
    rooted = (set(directives.include_symbols) - set(clean_directives.include_symbols)) | (
        set(directives.export_symbols) - set(clean_directives.export_symbols)
    )
    rows_by_name: dict[str, _CoffSymbol] = {}
    for name, sites in candidate_sites.items():
        expected_type = 0x20 if binding_kinds[name] == "function-rel32" else 0
        dependency_kind = "function" if expected_type == 0x20 else "data"
        if len(sites) != 1:
            raise ClassicSemanticError(
                f"ordered archive seed dependency {name!r} has {len(sites)} relocation sites"
            )
        rows = [symbol for symbol in effective.symbols if symbol.name == name]
        if (
            len(rows) != 1
            or rows[0].storage != 2
            or rows[0].section != 0
            or rows[0].value != 0
            or rows[0].symbol_type != expected_type
            or rows[0].auxiliary_count != 0
        ):
            raise ClassicSemanticError(
                f"ordered archive seed dependency {name!r} lacks one exact "
                f"undefined {dependency_kind} row"
            )
        if name in rooted:
            raise ClassicSemanticError(
                f"ordered archive seed dependency {name!r} is also a rooted linker control"
            )
        foreign_sections = sorted(
            {
                candidate.number
                for candidate in effective.sections
                if not candidate.name.casefold().startswith(".debug")
                for relocation in candidate.relocations
                if relocation.target == name and candidate.number != helper_section
            }
        )
        if foreign_sections:
            raise ClassicSemanticError(
                f"ordered archive seed dependency {name!r} is referenced outside "
                f"SeedOrder: {foreign_sections}"
            )
        rows_by_name[name] = rows[0]

    ordered_sites = sorted(
        ((sites[0][0], name, sites[0][1], sites[0][2]) for name, sites in candidate_sites.items()),
        key=lambda item: (item[0], item[1]),
    )
    if len({offset for offset, _name, _type, _addend in ordered_sites}) != len(ordered_sites):
        raise ClassicSemanticError("ordered archive seed dependencies share a relocation seat")
    first_use_names = tuple(name for _offset, name, _type, _addend in ordered_sites)
    undefined_rows = tuple(symbol for symbol in effective.symbols if symbol.name in candidate_sites)
    undefined_names = tuple(symbol.name for symbol in undefined_rows)
    if undefined_names != tuple(reversed(first_use_names)):
        raise ClassicSemanticError(
            "ordered archive seed undefined rows do not reverse first-use order"
        )
    undefined_ordinals = {symbol.name: ordinal for ordinal, symbol in enumerate(undefined_rows)}

    result: list[_OrderedArchiveSeedDependency] = []
    for first_use_ordinal, (offset, name, relocation_type, addend) in enumerate(ordered_sites):
        row = rows_by_name[name]
        result.append(
            _OrderedArchiveSeedDependency(
                helper_identifier=helper_identifier,
                helper_symbol=helper_symbol,
                helper_section=helper_section,
                policy=policy,
                binding_kind=binding_kinds[name],
                name=name,
                symbol_type=row.symbol_type,
                relocation_offset=offset,
                relocation_type=relocation_type,
                addend=addend,
                first_use_ordinal=first_use_ordinal,
                undefined_symbol_index=row.index,
                undefined_row_ordinal=undefined_ordinals[name],
            )
        )
    return tuple(result)


def _compiler_namespace_member_wire(
    value: CompilerSourceRead,
) -> dict[str, object]:
    return {
        "reference": value.reference,
        "digest": value.digest.model_dump(mode="json"),
        "size": value.size,
        "parent_index": value.parent_index,
    }


def compiler_namespace_evidence_digest(value: CompilerNamespaceEvidence) -> Digest:
    """Content-identify one complete shared compiler namespace census."""

    return Digest.from_bytes(
        canonical_json(
            {
                "schema": 1,
                "namespace_id": value.namespace_id,
                "input_evidence_kind": value.input_evidence_kind.value,
                "members": [_compiler_namespace_member_wire(item) for item in value.members],
            }
        )
    )


def _compiler_epoch_command_statement(
    value: CompilerEpochInvocation,
) -> dict[str, object]:
    return {
        "schema": 3,
        "input_evidence_kind": value.input_evidence_kind.value,
        "tool_id": value.tool_id,
        "tool_digest": value.tool_digest.model_dump(mode="json"),
        "arguments": list(value.arguments),
        "working_directory": value.working_directory,
        "environment_digest": value.environment_digest.model_dump(mode="json"),
        "path_profile_digest": value.path_profile_digest.model_dump(mode="json"),
    }


def compiler_epoch_invocation_digest(value: CompilerEpochInvocation) -> Digest:
    """Digest one command and its referenced shared compiler namespace."""

    return Digest.from_bytes(
        canonical_json(
            {
                **_compiler_epoch_command_statement(value),
                "namespace_id": value.namespace_id,
                "namespace_digest": value.namespace_digest.model_dump(mode="json"),
                "namespace_count": value.namespace_count,
            }
        )
    )


def classic_compiler_path_profile_digest(
    bundle: ProjectBundle, graph: ProducerGraphDocument
) -> Digest:
    """Bind the logical source/build/toolchain seats used by compiler epochs."""

    return Digest.from_bytes(
        canonical_json(
            {
                "schema": 1,
                "profile_id": graph.path_profile_id,
                "paths": bundle.spec.paths.model_dump(mode="json"),
            }
        )
    )


def _portable_tree_statement(
    *,
    relative_root: str,
    files: Mapping[str, CompilerSourceRead],
) -> dict[str, object]:
    """Rebuild one locked portable-tree-v1 receipt from immutable file bytes."""

    directory_children: dict[str, set[tuple[str, str]]] = defaultdict(set)
    file_by_relative: dict[str, CompilerSourceRead] = {}
    for relative, receipt in files.items():
        path = PurePosixPath(relative)
        if (
            path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ClassicSemanticError(
                f"toolchain tree {relative_root!r} has a malformed member {relative!r}"
            )
        file_by_relative[relative] = receipt
        parent = "."
        for index, part in enumerate(path.parts):
            kind = "file" if index + 1 == len(path.parts) else "directory"
            directory_children[parent].add((part, kind))
            if kind == "directory":
                parent = part if parent == "." else f"{parent}/{part}"

    records: list[dict[str, object]] = [{"path": ".", "type": "directory"}]
    maximum_depth = 0

    def emit(directory: str, depth: int) -> None:
        nonlocal maximum_depth
        maximum_depth = max(maximum_depth, depth)
        children = sorted(
            directory_children.get(directory, set()),
            key=lambda item: (item[0].casefold(), item[0]),
        )
        folded = [name.casefold() for name, _kind in children]
        if len(folded) != len(set(folded)):
            raise ClassicSemanticError(f"toolchain tree {relative_root!r} has a casefold collision")
        for name, kind in children:
            relative = name if directory == "." else f"{directory}/{name}"
            if kind == "directory":
                records.append({"path": relative, "type": "directory"})
                emit(relative, depth + 1)
            else:
                receipt = file_by_relative.get(relative)
                if receipt is None:
                    raise AssertionError("portable-tree file receipt disappeared")
                records.append(
                    {
                        "path": relative,
                        "type": "file",
                        "executable": False,
                        "size": receipt.size,
                        "sha256": receipt.digest.value,
                    }
                )

    emit(".", 0)
    membership_records = [
        {key: value for key, value in record.items() if key != "sha256"} for record in records
    ]
    membership = hashlib.sha256(
        json.dumps(membership_records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    content = hashlib.sha256(
        json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "path": relative_root,
        "entry_count": len(records),
        "max_depth": maximum_depth,
        "membership_digest": membership,
        "content_digest": content,
    }


def _toolchain_namespace_trace(
    *,
    bundle: ProjectBundle,
    reads: Sequence[CompilerSourceRead],
    node_id: str,
    epoch: str,
) -> dict[str, object]:
    toolchain_reads: dict[str, CompilerSourceRead] = {}
    for read in reads:
        if not read.reference.startswith("toolchain/"):
            continue
        relative = read.reference.removeprefix("toolchain/")
        previous = toolchain_reads.setdefault(relative.casefold(), read)
        if previous is not read:
            raise ClassicSemanticError(
                f"compiler {node_id!r} {epoch} repeats a toolchain namespace path"
            )
    covered: set[str] = set()
    direct_trace: list[dict[str, object]] = []
    for item in (*bundle.toolchain_lock.tools, *bundle.toolchain_lock.runtime_files):
        locked_read = toolchain_reads.get(item.path.casefold())
        if (
            locked_read is None
            or locked_read.reference != f"toolchain/{item.path}"
            or (
                locked_read.digest != item.digest
                or (item.size is not None and locked_read.size != item.size)
            )
        ):
            raise ClassicSemanticError(
                f"compiler {node_id!r} {epoch} omits locked toolchain file {item.path!r}"
            )
        covered.add(item.path.casefold())
        direct_trace.append(
            {
                "id": item.id,
                "path": item.path,
                "digest": item.digest.model_dump(mode="json"),
                "size": locked_read.size,
            }
        )

    tree_trace: list[dict[str, object]] = []
    tree_owners: dict[str, str] = {}
    for tree in bundle.toolchain_lock.input_trees:
        prefix = tree.path.rstrip("/") + "/"
        members: dict[str, CompilerSourceRead] = {}
        for folded, read in toolchain_reads.items():
            relative = read.reference.removeprefix("toolchain/")
            if not relative.startswith(prefix):
                continue
            member = relative[len(prefix) :]
            if not member:
                continue
            previous_owner = tree_owners.setdefault(folded, tree.id)
            if previous_owner != tree.id:
                raise ClassicSemanticError(
                    f"toolchain namespace path {relative!r} belongs to overlapping trees"
                )
            members[member] = read
            covered.add(folded)
        statement = _portable_tree_statement(
            relative_root=tree.path,
            files=members,
        )
        if (
            statement["entry_count"] != tree.entry_count
            or statement["max_depth"] != tree.max_depth
            or statement["membership_digest"] != tree.membership_digest.value
            or statement["content_digest"] != tree.content_digest.value
        ):
            raise ClassicSemanticError(
                f"compiler {node_id!r} {epoch} toolchain tree {tree.id!r} "
                "differs from its locked complete namespace"
            )
        tree_trace.append({"id": tree.id, **statement})
    if set(toolchain_reads) != covered:
        raise ClassicSemanticError(
            f"compiler {node_id!r} {epoch} toolchain namespace has undeclared files: "
            f"{sorted(set(toolchain_reads) - covered)}"
        )
    return {
        "locked_files": direct_trace,
        "input_trees": tree_trace,
        "file_count": len(toolchain_reads),
    }


@dataclass(frozen=True, slots=True)
class _ValidatedCompilerNamespace:
    namespace_id: str
    namespace_digest: Digest
    member_count: int
    members_trace_digest: Digest
    source_members: Mapping[str, tuple[str, Digest, int]]
    toolchain_trace: Mapping[str, object]
    macro_mutations: frozenset[tuple[str, str]]
    sensitive_macro_mutation_origins: frozenset[tuple[str, str, str]]
    global_declaration_origins: frozenset[tuple[str, str]]


def _namespace_preprocessor_mutations(
    members: Sequence[CompilerSourceRead],
    *,
    cache: dict[tuple[Digest, int], frozenset[tuple[str, str]]],
    sensitive_identifiers: frozenset[str],
) -> tuple[frozenset[tuple[str, str]], frozenset[tuple[str, str, str]]]:
    """Census all mutations and retain origins only for sensitive names."""

    result: set[tuple[str, str]] = set()
    sensitive_origins: set[tuple[str, str, str]] = set()
    for member in members:
        mutations = _payload_preprocessor_mutations(
            (member.payload,),
            prevalidated_digests=(member.digest,),
            cache=cache,
        )
        result.update(mutations)
        sensitive_origins.update(
            (member.reference, action, identifier)
            for action, identifier in mutations
            if identifier in sensitive_identifiers
        )
    return frozenset(result), frozenset(sensitive_origins)


def _compiler_namespace_toolchain_readers(
    bundle: ProjectBundle,
    evidences: Sequence[CompilerNamespaceEvidence],
) -> Mapping[str, bytes]:
    """Project complete namespaces down to locked preprocessor include trees."""

    prefixes = tuple(
        f"toolchain/{root.rstrip('/')}/".casefold() for root in _toolchain_include_roots(bundle)
    )
    readers: dict[str, bytes] = {}
    for evidence in evidences:
        for member in evidence.members:
            if not member.reference.casefold().startswith(prefixes):
                continue
            existing = readers.setdefault(member.reference, member.payload)
            if existing != member.payload:
                raise ClassicSemanticError(
                    f"toolchain namespace member changes between epochs: {member.reference!r}"
                )
    return MappingProxyType(readers)


def _namespace_global_declaration_origins(
    members: Sequence[CompilerSourceRead],
    *,
    bundle: ProjectBundle,
    identifiers: frozenset[str],
    cache: dict[tuple[Digest, int], frozenset[str]],
) -> frozenset[tuple[str, str]]:
    """Find generated entity spellings in every locked compiler include tree."""

    origins: set[tuple[str, str]] = set()
    if not identifiers:
        return frozenset()
    folded_roots = tuple(root.casefold().rstrip("/") for root in _toolchain_include_roots(bundle))
    for member in members:
        if not member.reference.startswith("toolchain/"):
            continue
        relative = member.reference.removeprefix("toolchain/").casefold()
        if not any(relative.startswith(root + "/") for root in folded_roots):
            continue
        key = (member.digest, member.size)
        hits = cache.get(key)
        if hits is None:
            hits = frozenset(
                token for token in _token_texts(member.payload) if token in identifiers
            )
            cache[key] = hits
        origins.update((member.reference, identifier) for identifier in hits)
    return frozenset(origins)


def _macro_capture_collisions(
    mutations: Iterable[tuple[str, str, str]],
    *,
    sensitive_identifiers: frozenset[str],
    intrinsic_source_mutations: frozenset[tuple[str, str, str]],
) -> tuple[str, ...]:
    """Find hostile mutations while admitting a record header's own guard."""

    collisions: set[str] = set()
    for reference, action, identifier in mutations:
        if identifier not in sensitive_identifiers:
            continue
        kind, separator, relative = reference.partition("/")
        if (
            separator
            and kind == "source"
            and (
                relative.casefold(),
                action,
                identifier,
            )
            in intrinsic_source_mutations
        ):
            continue
        collisions.add(identifier)
    return tuple(sorted(collisions))


def _compiler_namespace_member_trace(
    evidence: CompilerNamespaceEvidence,
) -> tuple[list[dict[str, object]], dict[str, tuple[str, Digest, int]]]:
    reads = evidence.members
    references = tuple(read.reference for read in reads)
    folded_references = {reference.casefold() for reference in references}
    if len(folded_references) != len(references) or references != tuple(
        sorted(references, key=lambda item: (item.casefold(), item))
    ):
        raise ClassicSemanticError(
            f"compiler namespace {evidence.namespace_id!r} census is not canonical"
        )
    result: list[dict[str, object]] = []
    source_members: dict[str, tuple[str, Digest, int]] = {}
    for index, raw in enumerate(reads):
        if not isinstance(raw, CompilerSourceRead):
            raise ClassicSemanticError(
                f"compiler namespace {evidence.namespace_id!r} member {index} is malformed"
            )
        if raw.size < 0 or raw.parent_index is not None:
            raise ClassicSemanticError(
                f"compiler namespace {evidence.namespace_id!r} member {index} "
                "claims observed include ancestry"
            )
        if (
            type(raw.payload) is not bytes
            or len(raw.payload) != raw.size
            or Digest.from_bytes(raw.payload) != raw.digest
        ):
            raise ClassicSemanticError(
                f"compiler namespace {evidence.namespace_id!r} member {index} bytes changed"
            )
        if "/" not in raw.reference:
            raise ClassicSemanticError(
                f"compiler namespace {evidence.namespace_id!r} member {index} has no authority"
            )
        kind, relative = raw.reference.split("/", 1)
        _relative(relative, label="compiler namespace member")
        if kind == "source":
            source_members[relative.casefold()] = (
                relative,
                raw.digest,
                raw.size,
            )
        elif kind != "toolchain":
            raise ClassicSemanticError(
                f"compiler namespace {evidence.namespace_id!r} escapes source/toolchain authority"
            )
        result.append(_compiler_namespace_member_wire(raw))
    return result, source_members


def _require_namespace_source_authority(
    namespace: _ValidatedCompilerNamespace,
    authority: Mapping[str, tuple[str, Digest, int]],
    *,
    epoch: str,
) -> None:
    if namespace.source_members != authority:
        missing = sorted(set(authority) - set(namespace.source_members))
        extra = sorted(set(namespace.source_members) - set(authority))
        changed = sorted(
            key
            for key in set(authority) & set(namespace.source_members)
            if namespace.source_members[key] != authority[key]
        )
        raise ClassicSemanticError(
            f"compiler namespace {namespace.namespace_id!r} differs from the "
            f"{epoch} source authority; missing={missing}, extra={extra}, "
            f"changed={changed}"
        )


def _validate_compiler_namespaces(
    *,
    bundle: ProjectBundle,
    evidences: Sequence[CompilerNamespaceEvidence],
    referenced_ids: frozenset[str],
    sensitive_identifiers: frozenset[str],
    global_declaration_identifiers: frozenset[str] = frozenset(),
    preprocessor_cache: dict[tuple[Digest, int], frozenset[tuple[str, str]]] | None = None,
    identifier_cache: dict[tuple[Digest, int], frozenset[str]] | None = None,
) -> dict[str, _ValidatedCompilerNamespace]:
    indexed = _unique(evidences, lambda item: item.namespace_id, "compiler namespace")
    expected_ids = {item.casefold() for item in referenced_ids}
    if set(indexed) != expected_ids:
        missing = sorted(expected_ids - set(indexed))
        extra = sorted(set(indexed) - expected_ids)
        raise ClassicSemanticError(
            f"shared compiler namespace universe differs; missing={missing}, extra={extra}"
        )
    result: dict[str, _ValidatedCompilerNamespace] = {}
    mutation_cache = {} if preprocessor_cache is None else preprocessor_cache
    declaration_cache = {} if identifier_cache is None else identifier_cache
    for folded, raw in indexed.items():
        if (
            not isinstance(raw, CompilerNamespaceEvidence)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", raw.namespace_id) is None
            or raw.input_evidence_kind is not CompilerInputEvidenceKind.COMPLETE_READABLE_NAMESPACE
            or raw.namespace_digest != compiler_namespace_evidence_digest(raw)
        ):
            raise ClassicSemanticError(
                f"compiler namespace evidence {getattr(raw, 'namespace_id', None)!r} changed"
            )
        members_trace, source_members = _compiler_namespace_member_trace(raw)
        toolchain_trace = _toolchain_namespace_trace(
            bundle=bundle,
            reads=raw.members,
            node_id=raw.namespace_id,
            epoch="shared",
        )
        macro_mutations, sensitive_macro_mutation_origins = _namespace_preprocessor_mutations(
            raw.members,
            cache=mutation_cache,
            sensitive_identifiers=sensitive_identifiers,
        )
        global_declaration_origins = _namespace_global_declaration_origins(
            raw.members,
            bundle=bundle,
            identifiers=global_declaration_identifiers,
            cache=declaration_cache,
        )
        if global_declaration_origins:
            raise ClassicSemanticError(
                "generated global declaration identifier already exists in the readable "
                f"toolchain namespace: {sorted(global_declaration_origins)}"
            )
        result[folded] = _ValidatedCompilerNamespace(
            raw.namespace_id,
            raw.namespace_digest,
            len(raw.members),
            Digest.from_bytes(canonical_json(members_trace)),
            MappingProxyType(source_members),
            MappingProxyType(toolchain_trace),
            macro_mutations,
            sensitive_macro_mutation_origins,
            global_declaration_origins,
        )
    return result


def _validate_compiler_invocation(
    *,
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    node: ProducerNode,
    invocation: CompilerEpochInvocation,
    namespaces: Mapping[str, _ValidatedCompilerNamespace],
    epoch: str,
) -> Digest:
    compiler_tools = [tool for tool in bundle.toolchain_lock.tools if "compiler" in tool.roles]
    if len(compiler_tools) != 1:
        raise ClassicSemanticError("toolchain does not lock exactly one compiler")
    tool = compiler_tools[0]
    expected_path_profile = classic_compiler_path_profile_digest(bundle, graph)
    namespace = namespaces.get(invocation.namespace_id.casefold())
    if (
        invocation.input_evidence_kind is not CompilerInputEvidenceKind.COMPLETE_READABLE_NAMESPACE
        or namespace is None
        or invocation.namespace_id != namespace.namespace_id
        or invocation.namespace_digest != namespace.namespace_digest
        or invocation.namespace_count != namespace.member_count
        or invocation.tool_id != tool.id
        or invocation.tool_digest != tool.digest
        or invocation.arguments != node.arguments
        or invocation.working_directory != bundle.spec.paths.build
        or invocation.path_profile_digest != expected_path_profile
        or invocation.invocation_digest != compiler_epoch_invocation_digest(invocation)
    ):
        raise ClassicSemanticError(
            f"compiler {node.id!r} {epoch} invocation differs from its locked graph"
        )
    return expected_path_profile


@dataclass(frozen=True, slots=True)
class _ArtifactSemanticsDecision:
    """The closed runtime theorem one audited compiler product cites, if any."""

    proven: bool
    runtime_projection_theorem: str | None
    runtime_projection_proof: Mapping[str, object] | None
    artifact_semantics_theorem: str | None


@dataclass(frozen=True, slots=True)
class _ProjectCompilerArtifactPair:
    """The closed artifact proof for two outputs of one locked compiler."""

    projection: _RuntimeProjectionEquivalence
    coff_trace: Mapping[str, object]
    decision: _ArtifactSemanticsDecision


@dataclass(frozen=True, slots=True)
class _ProjectCompilerEpochPair:
    """The shared proof result for one effective/counterfactual compiler pair."""

    counterfactual: _CoffObject
    effective: _CoffObject
    excluded_sections: frozenset[int]
    helper_definitions: frozenset[str]
    crt_pull_dependencies: tuple[_CrtPullLinkerDependency, ...]
    ordered_archive_seed_dependencies: tuple[_OrderedArchiveSeedDependency, ...]
    invocation_trace: Mapping[str, object]
    projection: _RuntimeProjectionEquivalence
    coff_trace: Mapping[str, object]
    decision: _ArtifactSemanticsDecision


def _artifact_semantics_decision(
    *,
    projection_required: bool,
    projection_equal: bool,
    projection_byte_equal: bool,
    projection_theorem: str | None,
    projection_proof: Mapping[str, object] | None,
    compiler_state_projection: object,
    coff_trace: Mapping[str, object],
    counterfactual_digest: object,
    effective_digest: object,
) -> _ArtifactSemanticsDecision:
    """Decide which closed theorem certifies an audited product's artifact semantics.

    A projection-required product cites a runtime projection theorem, the
    typed MSVC 4.20 compiler-state code theorem over its changed code
    sections, or exact byte equality.  When the declaration counterfactual
    and the effective compile retain byte-identical code in every paired
    section, there is no code delta left for a delta theorem to cover; the
    closed COFF semantic envelope congruence the trace already proved is then
    the complete artifact-semantics theorem (identical code is the strongest
    case of a proven code delta, so this widens nothing).
    """

    compiler_state_theorem = (
        compiler_state_projection.get("theorem")
        if isinstance(compiler_state_projection, dict)
        else None
    )
    changed_code_sections = coff_trace.get("changed_code_section_count")
    identical_code = (
        type(changed_code_sections) is int
        and changed_code_sections == 0
        and isinstance(coff_trace.get("theorem"), str)
    )
    runtime_projection_theorem: str | None
    runtime_projection_proof: Mapping[str, object] | None
    if projection_theorem is not None:
        runtime_projection_theorem = projection_theorem
        runtime_projection_proof = projection_proof
    elif isinstance(compiler_state_theorem, str):
        runtime_projection_theorem = compiler_state_theorem
        runtime_projection_proof = (
            projection_proof
            if projection_proof is not None
            else cast(Mapping[str, object], compiler_state_projection)
        )
    elif projection_byte_equal:
        runtime_projection_theorem = "exact-runtime-projection-v1"
        runtime_projection_proof = (
            projection_proof
            if projection_proof is not None
            else {
                "theorem": "exact-runtime-projection-v1",
                "counterfactual_object": counterfactual_digest,
                "effective_object": effective_digest,
            }
        )
    elif identical_code:
        runtime_projection_theorem = str(coff_trace["theorem"])
        runtime_projection_proof = (
            projection_proof
            if projection_proof is not None
            else {
                "theorem": str(coff_trace["theorem"]),
                "changed_code_section_count": 0,
                "counterfactual_object": counterfactual_digest,
                "effective_object": effective_digest,
            }
        )
    else:
        runtime_projection_theorem = None
        runtime_projection_proof = projection_proof
    proven = (
        (projection_equal or isinstance(compiler_state_theorem, str) or identical_code)
        if projection_required
        else True
    )
    return _ArtifactSemanticsDecision(
        proven,
        runtime_projection_theorem,
        runtime_projection_proof,
        runtime_projection_theorem if projection_required else str(coff_trace["theorem"]),
    )


def _project_compiler_artifact_pair(
    *,
    bundle: ProjectBundle,
    compiler_invocation: CompilerEpochInvocation,
    counterfactual: _CoffObject,
    effective: _CoffObject,
    excluded_sections: frozenset[int] = frozenset(),
    crt_pull_dependencies: tuple[_CrtPullLinkerDependency, ...] = (),
    ordered_archive_seed_dependencies: tuple[_OrderedArchiveSeedDependency, ...] = (),
    projection_required: bool,
) -> _ProjectCompilerArtifactPair:
    """Apply the cold audit's closed COFF proof to one compiler-object pair."""

    projection = _runtime_projection_equivalence_proof(
        counterfactual,
        effective,
        excluded_effective_sections=excluded_sections,
    )
    compiler_identity = (
        issue_msvc420_compiler_identity(bundle.toolchain_lock)
        if bundle.spec.toolchain.profile == bundle.toolchain_lock.profile
        else None
    )
    coff_trace = _coff_compiler_congruence_trace(
        counterfactual,
        effective,
        excluded_effective_sections=excluded_sections,
        projection_equivalence=projection,
        crt_pull_dependencies=crt_pull_dependencies,
        ordered_archive_seed_dependencies=ordered_archive_seed_dependencies,
        compiler_state_identity=compiler_identity,
        compiler_state_evidence=CompilerStateCompilerEvidence(
            tool_id=compiler_invocation.tool_id,
            tool_digest=compiler_invocation.tool_digest.value,
            invocation_digest=compiler_invocation.invocation_digest.value,
            arguments=compiler_invocation.arguments,
        ),
        compiler_state_projection_required=projection_required,
    )
    decision = _artifact_semantics_decision(
        projection_required=projection_required,
        projection_equal=projection.equivalent,
        projection_byte_equal=projection.byte_equal,
        projection_theorem=projection.theorem,
        projection_proof=projection.proof,
        compiler_state_projection=coff_trace.get("compiler_state_projection_proof"),
        coff_trace=coff_trace,
        counterfactual_digest=counterfactual.digest.model_dump(mode="json"),
        effective_digest=effective.digest.model_dump(mode="json"),
    )
    return _ProjectCompilerArtifactPair(projection, coff_trace, decision)


def _counterfactual_compiler_congruence_trace(
    *,
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    node: ProducerNode,
    audit: ProjectOverlayCounterfactualAudit,
    effective_invocation: CompilerEpochInvocation,
    namespaces: Mapping[str, _ValidatedCompilerNamespace],
) -> dict[str, object]:
    counterfactual_invocation = audit.counterfactual_invocation
    if not isinstance(counterfactual_invocation, CompilerEpochInvocation):
        raise ClassicSemanticError(
            f"compiler {node.id!r} lacks its declaration-counterfactual invocation"
        )
    expected_path_profile: Digest | None = None
    for epoch, invocation in (
        ("declaration-counterfactual", counterfactual_invocation),
        ("effective", effective_invocation),
    ):
        expected_path_profile = _validate_compiler_invocation(
            bundle=bundle,
            graph=graph,
            node=node,
            invocation=invocation,
            namespaces=namespaces,
            epoch=epoch,
        )
    if expected_path_profile is None:
        raise AssertionError("compiler invocation validation did not run")
    if _compiler_epoch_command_statement(
        counterfactual_invocation
    ) != _compiler_epoch_command_statement(effective_invocation):
        raise ClassicSemanticError(
            f"compiler {node.id!r} counterfactual/effective invocation differs"
        )
    return {
        "input_evidence_kind": counterfactual_invocation.input_evidence_kind.value,
        "counterfactual_invocation_digest": (
            counterfactual_invocation.invocation_digest.model_dump(mode="json")
        ),
        "effective_invocation_digest": effective_invocation.invocation_digest.model_dump(
            mode="json"
        ),
        "tool": {
            "id": counterfactual_invocation.tool_id,
            "digest": counterfactual_invocation.tool_digest.model_dump(mode="json"),
        },
        "arguments_digest": Digest.from_bytes(canonical_json(list(node.arguments))).model_dump(
            mode="json"
        ),
        "working_directory": bundle.spec.paths.build,
        "environment_digest": counterfactual_invocation.environment_digest.model_dump(mode="json"),
        "path_profile_digest": expected_path_profile.model_dump(mode="json"),
        "counterfactual_namespace": {
            "id": counterfactual_invocation.namespace_id,
            "digest": counterfactual_invocation.namespace_digest.model_dump(mode="json"),
            "count": counterfactual_invocation.namespace_count,
        },
        "effective_namespace": {
            "id": effective_invocation.namespace_id,
            "digest": effective_invocation.namespace_digest.model_dump(mode="json"),
            "count": effective_invocation.namespace_count,
        },
    }


def _validate_project_compiler_epoch_pair(
    *,
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    node: ProducerNode,
    audit: ProjectOverlayCounterfactualAudit,
    effective_invocation: CompilerEpochInvocation,
    namespaces: Mapping[str, _ValidatedCompilerNamespace],
    source_validation: _OverlaySourceValidation,
    counterfactual: _CoffObject,
    effective: _CoffObject,
) -> _ProjectCompilerEpochPair:
    """Validate one compiler pair with the same proof used by the cold audit."""

    source_ref, _object_ref = _compiler_shape(node)
    source_path = source_ref.removeprefix("source/").casefold()
    helpers = source_validation.helpers_by_source.get(source_path, ())
    excluded: frozenset[int] = frozenset()
    extra_definitions: frozenset[str] = frozenset()
    if helpers:
        excluded, extra_definitions = _helper_delta_sections(
            clean=counterfactual,
            effective=effective,
            helper_identifiers=helpers,
        )
    pull_dependencies = _crt_pull_linker_dependencies(
        clean=counterfactual,
        effective=effective,
        excluded_sections=excluded,
        helper_identifiers=source_validation.crt_pull_helpers_by_source.get(source_path, ()),
    )
    seed_dependencies = _seed_order_dependencies(
        clean=counterfactual,
        effective=effective,
        excluded_sections=excluded,
        seed_helpers=source_validation.ordered_archive_seed_helpers_by_source.get(
            source_path,
            (),
        ),
    )
    invocation_trace = _counterfactual_compiler_congruence_trace(
        bundle=bundle,
        graph=graph,
        node=node,
        audit=audit,
        effective_invocation=effective_invocation,
        namespaces=namespaces,
    )
    projection_required = (
        node.id in source_validation.compiler_epoch_plan.runtime_projection_node_ids
    )
    artifact_pair = _project_compiler_artifact_pair(
        bundle=bundle,
        compiler_invocation=effective_invocation,
        counterfactual=counterfactual,
        effective=effective,
        excluded_sections=excluded,
        crt_pull_dependencies=pull_dependencies,
        ordered_archive_seed_dependencies=seed_dependencies,
        projection_required=projection_required,
    )
    if projection_required and not artifact_pair.decision.proven:
        raise ClassicSemanticError(
            f"effective compiler {node.id!r} ({source_ref}) lacks a closed "
            "artifact-semantics theorem"
        )
    return _ProjectCompilerEpochPair(
        counterfactual,
        effective,
        excluded,
        extra_definitions,
        pull_dependencies,
        seed_dependencies,
        invocation_trace,
        artifact_pair.projection,
        artifact_pair.coff_trace,
        artifact_pair.decision,
    )


def _project_compiler_audit_trace(
    *,
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    products: Mapping[str, CompilerProduct],
    audits: Mapping[str, ProjectOverlayCounterfactualAudit],
    source_pairs: Mapping[str, ProjectOverlaySourcePair],
    clean_sources: Mapping[str, CleanSourceInput],
    generated_tus: frozenset[str],
    source_validation: _OverlaySourceValidation,
    namespace_evidences: Sequence[CompilerNamespaceEvidence],
    counterfactual_namespace_id: str,
) -> tuple[
    dict[str, _CoffObject],
    dict[str, _CoffObject],
    dict[str, frozenset[int]],
    dict[str, tuple[_CrtPullLinkerDependency, ...]],
    dict[str, tuple[_OrderedArchiveSeedDependency, ...]],
    list[dict[str, object]],
    list[dict[str, object]],
]:
    graph_compilers = {node.id: node for node in graph.nodes if node.role is ProducerRole.COMPILER}
    generated_tu_folded = {path.casefold() for path in generated_tus}
    _require_no_compiler_macro_capture(
        graph_compilers.values(),
        source_validation.macro_sensitive_identifiers,
    )
    ordinary_ids = {
        node_id
        for node_id, node in graph_compilers.items()
        if _compiler_shape(node)[0].removeprefix("source/").casefold() not in generated_tu_folded
    }
    generated_ids = set(graph_compilers) - ordinary_ids
    planned_audits = {
        node_id.casefold() for node_id in source_validation.compiler_epoch_plan.audit_node_ids
    }
    if set(audits) != planned_audits:
        missing = sorted(planned_audits - set(audits))
        extra = sorted(set(audits) - planned_audits)
        raise ClassicSemanticError(
            "declaration-counterfactual compiler audit universe differs; "
            f"missing={missing}, extra={extra}"
        )
    product_invocations: dict[str, CompilerEpochInvocation] = {}
    for node_id in graph_compilers:
        product = products.get(node_id.casefold())
        if not isinstance(product, CompilerProduct) or not isinstance(
            product.compiler_invocation, CompilerEpochInvocation
        ):
            raise ClassicSemanticError(
                f"compiler {node_id!r} lacks its effective namespace invocation evidence"
            )
        product_invocations[node_id] = product.compiler_invocation
    invocations = [
        invocation
        for audit in audits.values()
        for invocation in (audit.counterfactual_invocation,)
        if isinstance(invocation, CompilerEpochInvocation)
    ] + list(product_invocations.values())
    referenced_namespace_ids = frozenset(
        [counterfactual_namespace_id, *(invocation.namespace_id for invocation in invocations)]
    )
    namespaces = _validate_compiler_namespaces(
        bundle=bundle,
        evidences=namespace_evidences,
        referenced_ids=referenced_namespace_ids,
        sensitive_identifiers=source_validation.macro_sensitive_identifiers,
        global_declaration_identifiers=(source_validation.global_declaration_identifiers),
    )
    clean_authority = {
        item.path.casefold(): (
            item.path,
            Digest.from_bytes(item.payload),
            len(item.payload),
        )
        for item in clean_sources.values()
    }
    effective_authority = dict(clean_authority)
    for pair in source_pairs.values():
        if pair.path.casefold() in generated_tu_folded:
            continue
        effective_authority[pair.path.casefold()] = (
            pair.path,
            Digest.from_bytes(pair.effective_payload),
            len(pair.effective_payload),
        )
    generated_authority = dict(clean_authority)
    for pair in source_pairs.values():
        generated_authority[pair.path.casefold()] = (
            pair.path,
            Digest.from_bytes(pair.effective_payload),
            len(pair.effective_payload),
        )
    counterfactual_authority = dict(clean_authority)
    for path, payload in source_validation.compiler_epoch_plan.declaration_outputs.items():
        counterfactual_authority[path.casefold()] = (
            path,
            Digest.from_bytes(payload),
            len(payload),
        )
    counterfactual_id = counterfactual_namespace_id.casefold()
    if counterfactual_id not in namespaces:
        raise ClassicSemanticError("declaration-counterfactual namespace evidence is absent")
    _require_namespace_source_authority(
        namespaces[counterfactual_id],
        counterfactual_authority,
        epoch="declaration-counterfactual",
    )

    epoch_bindings: set[tuple[str, str]] = {("declaration-counterfactual", counterfactual_id)}
    for node_id, invocation in product_invocations.items():
        epoch = "generated" if node_id in generated_ids else "effective"
        epoch_bindings.add((epoch, invocation.namespace_id.casefold()))
        _validate_compiler_invocation(
            bundle=bundle,
            graph=graph,
            node=graph_compilers[node_id],
            invocation=invocation,
            namespaces=namespaces,
            epoch=epoch,
        )
        _require_namespace_source_authority(
            namespaces[invocation.namespace_id.casefold()],
            generated_authority if epoch == "generated" else effective_authority,
            epoch=epoch,
        )
    effective_namespace_ids = {
        product_invocations[node_id].namespace_id.casefold() for node_id in ordinary_ids
    }
    for effective_id in effective_namespace_ids:
        if set(namespaces[counterfactual_id].source_members) != set(
            namespaces[effective_id].source_members
        ):
            raise ClassicSemanticError(
                "counterfactual/effective compiler source namespace path universe differs"
            )
    for audit in audits.values():
        audit_invocation = audit.counterfactual_invocation
        if not isinstance(audit_invocation, CompilerEpochInvocation) or (
            audit_invocation.namespace_id.casefold() != counterfactual_id
        ):
            raise ClassicSemanticError(
                f"compiler {audit.node_id!r} has the wrong counterfactual namespace"
            )
    sensitive_macro_mutation_origins = frozenset(
        mutation
        for namespace in namespaces.values()
        for mutation in namespace.sensitive_macro_mutation_origins
    )
    macro_collisions = _macro_capture_collisions(
        sensitive_macro_mutation_origins,
        sensitive_identifiers=source_validation.macro_sensitive_identifiers,
        intrinsic_source_mutations=source_validation.intrinsic_macro_mutations,
    )
    if macro_collisions:
        raise ClassicSemanticError(
            "shared compiler namespace can macro-capture source-overlay identifiers; "
            f"read_definitions={macro_collisions}"
        )
    namespace_trace = [
        {
            "namespace_id": namespace.namespace_id,
            "namespace_digest": namespace.namespace_digest.model_dump(mode="json"),
            "member_count": namespace.member_count,
            "members_trace_digest": namespace.members_trace_digest.model_dump(mode="json"),
            "source_count": len(namespace.source_members),
            "epochs": sorted(
                epoch
                for epoch, namespace_id in epoch_bindings
                if namespace_id == namespace.namespace_id.casefold()
            ),
            "generated_compiler_nodes": sorted(
                node_id
                for node_id, invocation in product_invocations.items()
                if node_id in generated_ids
                if invocation.namespace_id.casefold() == namespace.namespace_id.casefold()
            ),
            "effective_compiler_nodes": sorted(
                node_id
                for node_id, invocation in product_invocations.items()
                if node_id in ordinary_ids
                if invocation.namespace_id.casefold() == namespace.namespace_id.casefold()
            ),
            "toolchain_namespace": namespace.toolchain_trace,
            "preprocessor_census_digest": Digest.from_bytes(
                canonical_json([list(item) for item in sorted(namespace.macro_mutations)])
            ).model_dump(mode="json"),
            "preprocessor_sensitive_origin_census_digest": Digest.from_bytes(
                canonical_json(
                    [
                        list(item)
                        for item in sorted(
                            namespace.sensitive_macro_mutation_origins,
                            key=lambda item: (
                                item[0].casefold(),
                                item[0],
                                item[1],
                                item[2],
                            ),
                        )
                    ]
                )
            ).model_dump(mode="json"),
            "global_declaration_toolchain_origin_census_digest": Digest.from_bytes(
                canonical_json(
                    [list(item) for item in sorted(namespace.global_declaration_origins)]
                )
            ).model_dump(mode="json"),
        }
        for namespace in sorted(namespaces.values(), key=lambda item: item.namespace_id.casefold())
    ]
    counterfactual_objects: dict[str, _CoffObject] = {}
    effective_objects: dict[str, _CoffObject] = {}
    helper_sections: dict[str, frozenset[int]] = {}
    crt_pull_dependencies: dict[str, tuple[_CrtPullLinkerDependency, ...]] = {}
    ordered_archive_seed_dependencies: dict[str, tuple[_OrderedArchiveSeedDependency, ...]] = {}
    trace: list[dict[str, object]] = []
    for node_id in sorted(ordinary_ids, key=str.casefold):
        product = products[node_id.casefold()]
        if not isinstance(product, CompilerProduct):
            raise ClassicSemanticError(f"effective compiler product changed: {node_id!r}")
        effective_objects[node_id] = _parse_coff(
            product.payload,
            f"effective:{product.object_ref}",
        )
    for node_id in sorted(source_validation.compiler_epoch_plan.audit_node_ids, key=str.casefold):
        node = graph_compilers[node_id]
        source_ref, object_ref = _compiler_shape(node)
        raw_audit = audits[node_id.casefold()]
        raw_product = products[node_id.casefold()]
        if not isinstance(raw_audit, ProjectOverlayCounterfactualAudit) or (
            raw_audit.node_id != node_id
            or raw_audit.source_ref != source_ref
            or raw_audit.object_ref != object_ref
            or type(raw_audit.counterfactual_payload) is not bytes
            or not raw_audit.counterfactual_payload
        ):
            raise ClassicSemanticError(
                f"declaration-counterfactual compiler audit changed: {node_id!r}"
            )
        if not isinstance(raw_product, CompilerProduct):
            raise ClassicSemanticError(f"effective compiler product changed: {node_id!r}")
        counterfactual = _parse_coff(
            raw_audit.counterfactual_payload,
            f"counterfactual:{object_ref}",
        )
        effective = effective_objects[node_id]
        effective_invocation = raw_product.compiler_invocation
        if not isinstance(effective_invocation, CompilerEpochInvocation):
            raise ClassicSemanticError(f"effective compiler {node_id!r} lacks invocation evidence")
        pair_proof = _validate_project_compiler_epoch_pair(
            bundle=bundle,
            graph=graph,
            node=node,
            audit=raw_audit,
            effective_invocation=effective_invocation,
            namespaces=namespaces,
            source_validation=source_validation,
            counterfactual=counterfactual,
            effective=effective,
        )
        counterfactual_objects[node_id] = pair_proof.counterfactual
        if pair_proof.excluded_sections:
            helper_sections[node_id] = pair_proof.excluded_sections
        if pair_proof.crt_pull_dependencies:
            crt_pull_dependencies[node_id] = pair_proof.crt_pull_dependencies
        if pair_proof.ordered_archive_seed_dependencies:
            ordered_archive_seed_dependencies[node_id] = (
                pair_proof.ordered_archive_seed_dependencies
            )
        projection_required = (
            node_id in source_validation.compiler_epoch_plan.runtime_projection_node_ids
        )
        runtime_projection_theorem = pair_proof.decision.runtime_projection_theorem
        runtime_projection_proof = pair_proof.decision.runtime_projection_proof
        artifact_semantics_proven = pair_proof.decision.proven
        artifact_semantics_theorem = pair_proof.decision.artifact_semantics_theorem
        trace.append(
            {
                "node_id": node_id,
                "source_ref": source_ref,
                "object_ref": object_ref,
                "counterfactual_digest": counterfactual.digest.value,
                "counterfactual_size": len(raw_audit.counterfactual_payload),
                "counterfactual_object": {
                    "digest": counterfactual.digest.model_dump(mode="json"),
                    "size": len(raw_audit.counterfactual_payload),
                },
                "effective_digest": effective.digest.value,
                "effective_size": len(raw_product.payload),
                "effective_object": {
                    "digest": effective.digest.model_dump(mode="json"),
                    "size": len(raw_product.payload),
                },
                "runtime_projection_required": projection_required,
                "runtime_projection_equal": pair_proof.projection.byte_equal,
                "runtime_projection_equivalent": pair_proof.projection.equivalent,
                "runtime_projection_byte_equal": pair_proof.projection.byte_equal,
                "runtime_projection_theorem": runtime_projection_theorem,
                "runtime_projection_proof": (
                    dict(runtime_projection_proof) if runtime_projection_proof is not None else None
                ),
                "artifact_semantics_required": projection_required,
                "artifact_semantics_proven": artifact_semantics_proven,
                "artifact_semantics_theorem": artifact_semantics_theorem,
                "compiler_congruence": pair_proof.invocation_trace,
                "coff_semantic_theorem": pair_proof.coff_trace,
                "helper_sections": sorted(pair_proof.excluded_sections),
                "helper_definitions": sorted(pair_proof.helper_definitions),
            }
        )
    return (
        counterfactual_objects,
        effective_objects,
        helper_sections,
        crt_pull_dependencies,
        ordered_archive_seed_dependencies,
        trace,
        namespace_trace,
    )


def validate_project_overlay_compiler_epoch(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    *,
    compiler_products: Sequence[CompilerProduct],
    project_source_pairs: Sequence[ProjectOverlaySourcePair],
    counterfactual_compiler_audits: Sequence[ProjectOverlayCounterfactualAudit],
    counterfactual_namespace_id: str,
    clean_source_inputs: Sequence[CleanSourceInput],
    compiler_namespaces: Sequence[CompilerNamespaceEvidence],
) -> Mapping[str, object]:
    """Fail fast on the independently derived project-overlay compiler theorem.

    This preflight intentionally recomputes the source plan instead of trusting
    the runtime's execution plan.  It validates every effective invocation and
    only compares object payloads for the exact sparse counterfactual audit set.
    The complete overlay proof repeats these checks after composition/linking.
    """

    plan, validation, generated_tus = _derive_project_overlay_compiler_epoch(
        bundle,
        graph,
        project_source_pairs,
        clean_source_inputs,
        secondary_reader_payloads=_compiler_namespace_toolchain_readers(
            bundle, compiler_namespaces
        ),
    )
    if validation is None:
        raise ClassicSemanticError("compiler epoch preflight requires a project overlay")
    products = _unique(compiler_products, lambda item: item.node_id, "compiler product")
    graph_compiler_ids = {
        node.id.casefold() for node in graph.nodes if node.role is ProducerRole.COMPILER
    }
    if set(products) != graph_compiler_ids:
        missing = sorted(graph_compiler_ids - set(products))
        extra = sorted(set(products) - graph_compiler_ids)
        raise ClassicSemanticError(
            f"compiler epoch preflight product universe differs; missing={missing}, extra={extra}"
        )
    audits = _unique(
        counterfactual_compiler_audits,
        lambda item: item.node_id,
        "declaration-counterfactual compiler audit",
    )
    (
        _counterfactual_objects,
        _effective_objects,
        _helper_sections,
        _crt_pull_dependencies,
        _ordered_archive_seed_dependencies_by_node,
        compiler_audit_trace,
        compiler_namespace_trace,
    ) = _project_compiler_audit_trace(
        bundle=bundle,
        graph=graph,
        products={
            key: value for key, value in products.items() if isinstance(value, CompilerProduct)
        },
        audits={
            key: value
            for key, value in audits.items()
            if isinstance(value, ProjectOverlayCounterfactualAudit)
        },
        source_pairs={item.path.casefold(): item for item in project_source_pairs},
        clean_sources={item.path.casefold(): item for item in clean_source_inputs},
        generated_tus=generated_tus,
        source_validation=validation,
        namespace_evidences=compiler_namespaces,
        counterfactual_namespace_id=counterfactual_namespace_id,
    )
    return MappingProxyType(
        {
            "schema": 1,
            "theorem": "sparse-project-overlay-compiler-epoch-preflight-v1",
            "counterfactual_output_count": len(plan.declaration_outputs),
            "audit_node_ids": sorted(plan.audit_node_ids, key=str.casefold),
            "runtime_projection_node_ids": sorted(
                plan.runtime_projection_node_ids,
                key=str.casefold,
            ),
            "compiler_audits": compiler_audit_trace,
            "compiler_namespaces": compiler_namespace_trace,
        }
    )


__all__ = [
    "classic_compiler_path_profile_digest",
    "compiler_epoch_invocation_digest",
    "compiler_namespace_evidence_digest",
    "validate_project_overlay_compiler_epoch",
]
