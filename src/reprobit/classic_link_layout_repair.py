"""Fail-closed diagnosis of classic selected-COMDAT order mismatches.

The result is only a targeting hint.  It never rewrites an image and never
claims byte identity; the normal rebuild and comparison remain authoritative.
"""

from __future__ import annotations

import struct
from collections import defaultdict
from dataclasses import dataclass
from pathlib import PurePosixPath

from reprobit.binary import ByteIdentityError
from reprobit.classic.link_topology import ClassicLinkTopologyError, terminal_link_input_topology
from reprobit.classic_project import ClassicProjectError
from reprobit.classic_runtime_graph import classic_compiler_product_refs
from reprobit.msvc42_pdb import (
    Msvc42PdbLinkMap,
    Msvc42PdbModule,
    Msvc42PdbSectionContribution,
    read_msvc42_pdb_link_map,
)
from reprobit.msvc42_pe_debug import read_msvc42_debug_companion_identity
from reprobit.paths import PathContractError, logical_relative_to, normalize_logical_path
from reprobit.pe32 import (
    Pe32Headers,
    Pe32Section,
    parse_pe32_headers,
    pe32_highlow_relocation_offsets,
)
from reprobit.producer_graph import ProducerGraphDocument, ProducerRole
from reprobit.schema import ProjectBundle

_IMAGE_SCN_CNT_CODE = 0x00000020
_IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
_IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
_IMAGE_SCN_LNK_COMDAT = 0x00001000


@dataclass(frozen=True, slots=True)
class ClassicLinkLayoutHint:
    """One compiler whose selected symbols need the declared relative order."""

    compiler_node_id: str
    desired_symbol_order: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ImageDifference:
    headers: Pe32Headers
    changed_sites: frozenset[int]


@dataclass(frozen=True, slots=True)
class _CoreProof:
    module_index: int
    core_start: int
    core_end: int
    desired_symbols: tuple[str, ...]
    candidate_symbol_vas: tuple[tuple[str, int], ...]
    oracle_symbol_vas: tuple[tuple[str, int], ...]


class _UnsupportedEvidence(ValueError):
    pass


def _need(condition: bool) -> None:
    if not condition:
        raise _UnsupportedEvidence


def _same_image_geometry(left: Pe32Headers, right: Pe32Headers) -> bool:
    def geometry(headers: Pe32Headers) -> tuple[tuple[bytes, int, int, int, int, int], ...]:
        return tuple(
            (
                section.raw_name,
                section.virtual_size,
                section.virtual_address,
                section.raw_size,
                section.raw_offset,
                section.characteristics,
            )
            for section in headers.sections
        )

    return left.image_base == right.image_base and geometry(left) == geometry(right)


def _image_difference(candidate: bytes, oracle: bytes) -> _ImageDifference:
    _need(len(candidate) == len(oracle))
    candidate_headers = parse_pe32_headers(candidate)
    oracle_headers = parse_pe32_headers(oracle)
    _need(_same_image_geometry(candidate_headers, oracle_headers))

    candidate_sites = pe32_highlow_relocation_offsets(candidate)
    oracle_sites = pe32_highlow_relocation_offsets(oracle)
    _need(candidate_sites == oracle_sites)
    changed_sites = frozenset(
        site for site in candidate_sites if candidate[site : site + 4] != oracle[site : site + 4]
    )
    _need(bool(changed_sites))

    relocation_owner: dict[int, int] = {}
    for site in candidate_sites:
        for offset in range(site, site + 4):
            _need(offset not in relocation_owner)
            relocation_owner[offset] = site
    for offset, (candidate_byte, oracle_byte) in enumerate(zip(candidate, oracle, strict=True)):
        if candidate_byte != oracle_byte:
            _need(relocation_owner.get(offset) in changed_sites)
    return _ImageDifference(candidate_headers, changed_sites)


def _section_for_site(headers: Pe32Headers, site: int) -> tuple[int, Pe32Section]:
    matches = tuple(
        (index, section)
        for index, section in enumerate(headers.sections, start=1)
        if section.holds_offset(site, 4)
    )
    _need(len(matches) == 1)
    return matches[0]


def _is_initialized_data(characteristics: int) -> bool:
    return bool(characteristics & _IMAGE_SCN_CNT_INITIALIZED_DATA) and not bool(
        characteristics & (_IMAGE_SCN_CNT_CODE | _IMAGE_SCN_CNT_UNINITIALIZED_DATA)
    )


def _initialized_data_changed_runs(
    headers: Pe32Headers,
    changed_sites: frozenset[int],
) -> tuple[tuple[int, tuple[int, ...]], ...]:
    by_section: dict[int, list[int]] = defaultdict(list)
    for site in sorted(changed_sites):
        section_index, section = _section_for_site(headers, site)
        if _is_initialized_data(section.characteristics):
            by_section[section_index].append(site)

    runs: list[tuple[int, tuple[int, ...]]] = []
    for section_index, sites in sorted(by_section.items()):
        current: list[int] = []
        for site in sites:
            if current and site != current[-1] + 4:
                runs.append((section_index, tuple(current)))
                current = []
            current.append(site)
        if current:
            runs.append((section_index, tuple(current)))
    return tuple(runs)


def _unique_occurrence(haystack: bytes, needle: bytes) -> int:
    _need(bool(needle))
    first = haystack.find(needle)
    _need(first >= 0)
    _need(haystack.find(needle, first + 1) < 0)
    return first


def _complete_contribution_run(
    link_map: Msvc42PdbLinkMap,
    *,
    section: int,
    start: int,
    end: int,
) -> tuple[Msvc42PdbSectionContribution, ...]:
    contributions = tuple(
        sorted(
            (
                contribution
                for contribution in link_map.contributions
                if contribution.section == section
                and contribution.offset < end
                and start < contribution.offset + contribution.size
            ),
            key=lambda contribution: contribution.offset,
        )
    )
    _need(len(contributions) >= 2)
    cursor = start
    for contribution in contributions:
        _need(contribution.offset == cursor)
        _need(_is_initialized_data(contribution.characteristics))
        _need(bool(contribution.characteristics & _IMAGE_SCN_LNK_COMDAT))
        cursor += contribution.size
    _need(cursor == end)
    _need(len({item.module_index for item in contributions}) == 1)
    return contributions


def _unique_public_names(
    link_map: Msvc42PdbLinkMap,
    contributions: tuple[Msvc42PdbSectionContribution, ...],
) -> tuple[str, ...]:
    publics_by_start: dict[tuple[int, int], list[str]] = defaultdict(list)
    for public in link_map.publics:
        publics_by_start[(public.section, public.offset)].append(public.name)
    names: list[str] = []
    for contribution in contributions:
        matches = publics_by_start[(contribution.section, contribution.offset)]
        _need(len(matches) == 1)
        names.append(matches[0])
    _need(len(names) == len(set(names)))
    return tuple(names)


def _unique_chunk_permutation(chunks: tuple[bytes, ...], oracle: bytes) -> tuple[int, ...]:
    _need(len(chunks) == len(set(chunks)))
    unused = set(range(len(chunks)))
    order: list[int] = []
    cursor = 0
    while unused:
        matches = tuple(index for index in unused if oracle.startswith(chunks[index], cursor))
        _need(len(matches) == 1)
        selected = matches[0]
        order.append(selected)
        cursor += len(chunks[selected])
        unused.remove(selected)
    _need(cursor == len(oracle))
    _need(order != list(range(len(chunks))))
    return tuple(order)


def _core_proof(
    *,
    candidate: bytes,
    oracle: bytes,
    debug: bytes,
    candidate_headers: Pe32Headers,
    debug_headers: Pe32Headers,
    link_map: Msvc42PdbLinkMap,
    section_index: int,
    sites: tuple[int, ...],
) -> _CoreProof:
    _need(bool(sites))
    section = candidate_headers.sections[section_index - 1]
    core_start, core_end = sites[0], sites[-1] + 4
    _need(tuple(range(core_start, core_end, 4)) == sites)
    core = candidate[core_start:core_end]

    debug_sections = tuple(
        (index, candidate_section)
        for index, candidate_section in enumerate(debug_headers.sections, start=1)
        if candidate_section.raw_name == section.raw_name
    )
    _need(len(debug_sections) == 1)
    debug_section_index, debug_section = debug_sections[0]
    _need(_is_initialized_data(debug_section.characteristics))
    debug_body = debug[debug_section.raw_offset : debug_section.raw_end]
    debug_start = _unique_occurrence(debug_body, core)
    debug_end = debug_start + len(core)

    contributions = _complete_contribution_run(
        link_map,
        section=debug_section_index,
        start=debug_start,
        end=debug_end,
    )
    names = _unique_public_names(link_map, contributions)
    chunks = tuple(debug_body[item.offset : item.offset + item.size] for item in contributions)
    _need(b"".join(chunks) == core)
    desired_indices = _unique_chunk_permutation(chunks, oracle[core_start:core_end])
    desired_symbols = tuple(names[index] for index in desired_indices)

    candidate_base = (
        candidate_headers.image_base + section.virtual_address + core_start - section.raw_offset
    )
    _need(candidate_base <= 0xFFFFFFFF)
    candidate_vas: list[tuple[str, int]] = []
    cursor = candidate_base
    for name, chunk in zip(names, chunks, strict=True):
        candidate_vas.append((name, cursor))
        cursor += len(chunk)

    oracle_vas_by_name: dict[str, int] = {}
    cursor = candidate_base
    for index in desired_indices:
        oracle_vas_by_name[names[index]] = cursor
        cursor += len(chunks[index])
    _need(cursor <= 0x100000000)
    return _CoreProof(
        module_index=contributions[0].module_index,
        core_start=core_start,
        core_end=core_end,
        desired_symbols=desired_symbols,
        candidate_symbol_vas=tuple(candidate_vas),
        oracle_symbol_vas=tuple((name, oracle_vas_by_name[name]) for name in names),
    )


def _outside_pointers_match(
    candidate: bytes,
    oracle: bytes,
    changed_sites: frozenset[int],
    proof: _CoreProof,
) -> bool:
    candidate_names = {address: name for name, address in proof.candidate_symbol_vas}
    if len(candidate_names) != len(proof.candidate_symbol_vas):
        return False
    oracle_vas = dict(proof.oracle_symbol_vas)
    for site in changed_sites:
        if proof.core_start <= site and site + 4 <= proof.core_end:
            continue
        if not (site + 4 <= proof.core_start or proof.core_end <= site):
            return False
        candidate_value = struct.unpack_from("<I", candidate, site)[0]
        oracle_value = struct.unpack_from("<I", oracle, site)[0]
        name = candidate_names.get(candidate_value)
        if name is None or oracle_vas[name] != oracle_value:
            return False
    return True


def _compiler_owner(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    target_id: str,
    module: Msvc42PdbModule,
) -> str:
    _need(sum(target.id == target_id for target in bundle.spec.targets) == 1)
    object_path = normalize_logical_path(module.object_name.replace("/", "\\"))
    relative = logical_relative_to(object_path, bundle.spec.paths.build)
    _need(str(relative) != ".")
    object_reference = "build/" + "/".join(relative.parts)

    owners = []
    for node in graph.nodes:
        if node.role is not ProducerRole.COMPILER:
            continue
        _source_reference, candidate_object = classic_compiler_product_refs(node)
        if candidate_object.casefold() == object_reference.casefold():
            owners.append(node)
    _need(len(owners) == 1)
    topology = terminal_link_input_topology(graph, target_id)
    _need(owners[0].id in topology.compiler_node_ids)
    return owners[0].id


def _expected_debug_pdb_path(bundle: ProjectBundle, target_id: str) -> str:
    targets = tuple(target for target in bundle.spec.targets if target.id == target_id)
    _need(len(targets) == 1)
    artifact = PurePosixPath(targets[0].artifact)
    _need(len(artifact.parts) >= 2 and artifact.parts[0].casefold() == "build")
    pdb_name = artifact.with_suffix(".PDB").name
    suffix = "\\".join((".reprobit-analysis", target_id, pdb_name))
    return normalize_logical_path(bundle.spec.paths.build.rstrip("\\") + "\\" + suffix)


def _derive_classic_link_layout_hint(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    *,
    target_id: str,
    candidate_image: bytes,
    oracle_image: bytes,
    debug_image: bytes,
    pdb: bytes,
) -> ClassicLinkLayoutHint:
    _need(all(type(value) is bytes for value in (candidate_image, oracle_image, debug_image, pdb)))
    difference = _image_difference(candidate_image, oracle_image)
    debug_headers = parse_pe32_headers(debug_image)
    link_map = read_msvc42_pdb_link_map(pdb)
    debug_identity = read_msvc42_debug_companion_identity(
        debug_image,
        expected_pdb_path=_expected_debug_pdb_path(bundle, target_id),
    )
    _need(debug_identity.pdb_identity == link_map.identity)
    _need(tuple(module.index for module in link_map.modules) == tuple(range(len(link_map.modules))))

    proofs: list[_CoreProof] = []
    for section_index, sites in _initialized_data_changed_runs(
        difference.headers,
        difference.changed_sites,
    ):
        try:
            proof = _core_proof(
                candidate=candidate_image,
                oracle=oracle_image,
                debug=debug_image,
                candidate_headers=difference.headers,
                debug_headers=debug_headers,
                link_map=link_map,
                section_index=section_index,
                sites=sites,
            )
        except _UnsupportedEvidence:
            continue
        if _outside_pointers_match(
            candidate_image,
            oracle_image,
            difference.changed_sites,
            proof,
        ):
            proofs.append(proof)
    _need(len(proofs) == 1)
    proof = proofs[0]
    _need(proof.module_index < len(link_map.modules))
    compiler_node_id = _compiler_owner(
        bundle,
        graph,
        target_id,
        link_map.modules[proof.module_index],
    )
    return ClassicLinkLayoutHint(compiler_node_id, proof.desired_symbols)


def derive_classic_link_layout_hint(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    *,
    target_id: str,
    candidate_image: bytes,
    oracle_image: bytes,
    debug_image: bytes,
    pdb: bytes,
) -> ClassicLinkLayoutHint | None:
    """Return one proven provider/order hint, or ``None`` for incomplete evidence."""

    try:
        return _derive_classic_link_layout_hint(
            bundle,
            graph,
            target_id=target_id,
            candidate_image=candidate_image,
            oracle_image=oracle_image,
            debug_image=debug_image,
            pdb=pdb,
        )
    except (
        ByteIdentityError,
        ClassicLinkTopologyError,
        ClassicProjectError,
        PathContractError,
        _UnsupportedEvidence,
    ):
        return None


__all__ = ["ClassicLinkLayoutHint", "derive_classic_link_layout_hint"]
