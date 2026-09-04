"""Candidate-only PE32 import-order normalization."""

from __future__ import annotations

import struct
from collections import Counter, defaultdict, deque
from collections.abc import Mapping
from dataclasses import dataclass
from itertools import pairwise

from reprobit.binary import require
from reprobit.pe32 import (
    Pe32Headers,
    parse_pe32_headers,
    pe32_highlow_relocation_offsets,
)

from .foundation import (
    canonical_json_bytes,
    exact_audit_keys,
    require_exact_int,
    require_payload_free_declaration,
    require_sha,
    sha256_bytes,
)

IMAGE_ORDINAL_FLAG32 = 0x80000000


@dataclass(frozen=True, slots=True)
class _Section:
    raw_descriptor: bytes
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int

    @property
    def raw_end(self) -> int:
        return self.raw_offset + self.raw_size


@dataclass(frozen=True, slots=True)
class _ImportEntry:
    slot_va: int
    thunk: int
    identity: tuple[str, str | int]


@dataclass(frozen=True, slots=True)
class _ImportDescriptor:
    raw_descriptor: bytes
    dll: str
    original_first_thunk: int
    first_thunk: int
    entries: tuple[_ImportEntry, ...]


def _cstring(data: bytes, offset: int, limit: int, context: str) -> bytes:
    require(0 <= offset < limit <= len(data), f"{context} is outside the file")
    end = data.find(b"\0", offset, limit)
    require(end >= 0, f"{context} is not NUL-terminated in its section")
    return data[offset:end]


class _PE32Imports:
    def __init__(self, data: bytes) -> None:
        self._headers: Pe32Headers = parse_pe32_headers(data, minimum_optional_size=144)
        directories = "import/base-relocation directories"
        self.data = data
        self.machine = self._headers.machine
        self.image_base = self._headers.image_base
        self.section_alignment = self._headers.section_alignment
        require(self.section_alignment != 0, "section alignment must be nonzero")
        self.import_rva, self.import_size = self._headers.data_directory(1, directories)
        self.reloc_rva, self.reloc_size = self._headers.data_directory(5, directories)
        sections = []
        for row in self._headers.sections:
            try:
                name = row.raw_name.rstrip(b"\0").decode("ascii")
            except UnicodeDecodeError as exc:
                raise ValueError("PE section name is not ASCII") from exc
            sections.append(
                _Section(
                    row.raw_descriptor,
                    name,
                    row.virtual_size,
                    row.virtual_address,
                    row.raw_size,
                    row.raw_offset,
                )
            )
        self.sections = tuple(sections)
        self.imports = self._parse_imports()

    def section_for_rva(self, rva: int, size: int = 1) -> _Section:
        require(size >= 0, "negative mapped size")
        row = self._headers.section_for_rva(rva, size, context=f"RVA 0x{rva:x}")
        return self.sections[self._headers.sections.index(row)]

    def rva_to_offset(self, rva: int, size: int = 1) -> int:
        section = self.section_for_rva(rva, size)
        return section.raw_offset + rva - section.virtual_address

    def cstring_at_rva(self, rva: int, context: str) -> bytes:
        section = self.section_for_rva(rva)
        offset = section.raw_offset + rva - section.virtual_address
        return _cstring(self.data, offset, section.raw_end, context)

    def _parse_imports(self) -> tuple[_ImportDescriptor, ...]:
        require(
            self.import_rva != 0 and self.import_size >= 40,
            "missing or undersized import directory",
        )
        require(self.import_size % 20 == 0, "import directory is not descriptor-aligned")
        start = self.rva_to_offset(self.import_rva, self.import_size)
        end = start + self.import_size
        descriptors: list[_ImportDescriptor] = []
        saw_terminator = False
        for offset in range(start, end, 20):
            raw = self.data[offset : offset + 20]
            if raw == b"\0" * 20:
                saw_terminator = True
                require(
                    not any(self.data[offset + 20 : end]), "nonzero descriptor follows terminator"
                )
                break
            original_first_thunk, _, _, name_rva, first_thunk = struct.unpack("<IIIII", raw)
            require(name_rva != 0, "import descriptor has a null Name RVA")
            require(original_first_thunk != 0, "bound imports are unsupported")
            require(first_thunk != 0, "import descriptor has a null FirstThunk")
            dll_raw = self.cstring_at_rva(name_rva, "import DLL name")
            require(bool(dll_raw), "import DLL name is empty")
            try:
                dll = dll_raw.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ValueError("import DLL name is not ASCII") from exc
            descriptors.append(
                _ImportDescriptor(
                    raw,
                    dll,
                    original_first_thunk,
                    first_thunk,
                    self._parse_entries(original_first_thunk, first_thunk, dll),
                )
            )
        require(saw_terminator, "import directory has no null terminator")
        require(bool(descriptors), "import directory contains no DLL descriptors")
        return tuple(descriptors)

    def _parse_entries(
        self, original_first_thunk: int, first_thunk: int, dll: str
    ) -> tuple[_ImportEntry, ...]:
        lookup_section = self.section_for_rva(original_first_thunk, 4)
        address_section = self.section_for_rva(first_thunk, 4)
        capacity = min(
            (lookup_section.raw_size - (original_first_thunk - lookup_section.virtual_address))
            // 4,
            (address_section.raw_size - (first_thunk - address_section.virtual_address)) // 4,
        )
        require(capacity > 0, f"{dll} has empty thunk arrays")
        entries: list[_ImportEntry] = []
        terminated = False
        for index in range(capacity):
            lookup = struct.unpack_from(
                "<I", self.data, self.rva_to_offset(original_first_thunk + index * 4, 4)
            )[0]
            address = struct.unpack_from(
                "<I", self.data, self.rva_to_offset(first_thunk + index * 4, 4)
            )[0]
            require(lookup == address, f"{dll} ILT/IAT entries differ at index {index}")
            if lookup == 0:
                terminated = True
                break
            if lookup & IMAGE_ORDINAL_FLAG32:
                require(
                    lookup & 0x7FFF0000 == 0,
                    f"{dll} has malformed ordinal thunk 0x{lookup:08x}",
                )
                ordinal = lookup & 0xFFFF
                require(ordinal != 0, f"{dll} imports invalid ordinal zero")
                identity: tuple[str, str | int] = ("ordinal", ordinal)
            else:
                name_raw = self.cstring_at_rva(lookup + 2, f"{dll} import name")
                require(bool(name_raw), f"{dll} has an empty import name")
                try:
                    name = name_raw.decode("ascii")
                except UnicodeDecodeError as exc:
                    raise ValueError(f"{dll} import name is not ASCII") from exc
                identity = ("name", name)
            entries.append(
                _ImportEntry(self.image_base + first_thunk + index * 4, lookup, identity)
            )
        require(terminated, f"{dll} thunk arrays have no null terminator")
        return tuple(entries)

    def highlow_relocation_offsets(self) -> set[int]:
        return set(pe32_highlow_relocation_offsets(self.data))

    def layout_digest(self) -> str:
        rows = []
        for section in self.sections:
            mapped = max(section.virtual_size, section.raw_size)
            mapped = (mapped + self.section_alignment - 1) // self.section_alignment
            normalized = (
                section.raw_descriptor[:8]
                + b"\0\0\0\0"
                + section.raw_descriptor[12:]
                + mapped.to_bytes(4, "little")
            )
            rows.append(normalized.hex())
        return sha256_bytes(canonical_json_bytes(rows))


def _identity_document(identity: tuple[str, str | int]) -> dict[str, object]:
    kind, value = identity
    return {"kind": kind, "value": value}


def capture_pe_import_order(image: bytes) -> dict[str, object]:
    """Capture payload-free import-order metadata for a manifest lock step."""

    parsed = _PE32Imports(image)
    return {
        "schema": "pe32_import_order_v1",
        "machine": parsed.machine,
        "image_base": parsed.image_base,
        "section_alignment": parsed.section_alignment,
        "section_layout_sha256": parsed.layout_digest(),
        "import_directory_rva": parsed.import_rva,
        "import_directory_size": parsed.import_size,
        "imports": [
            {
                "header_sha256": sha256_bytes(item.raw_descriptor),
                "dll": item.dll,
                "original_first_thunk": item.original_first_thunk,
                "first_thunk": item.first_thunk,
                "order": [_identity_document(entry.identity) for entry in item.entries],
            }
            for item in parsed.imports
        ],
    }


def _validated_declaration(value: object) -> dict[str, object]:
    require(isinstance(value, dict), "PE import-order declaration must be an object")
    assert isinstance(value, dict)
    exact_audit_keys(
        value,
        {
            "schema",
            "machine",
            "image_base",
            "section_alignment",
            "section_layout_sha256",
            "import_directory_rva",
            "import_directory_size",
            "imports",
        },
        "PE import-order declaration",
    )
    require(value.get("schema") == "pe32_import_order_v1", "unsupported import-order schema")
    descriptors = value.get("imports")
    require(isinstance(descriptors, list), "import descriptor plan must be an array")
    assert isinstance(descriptors, list)
    require(bool(descriptors), "import descriptor plan is empty")
    normalized: list[dict[str, object]] = []
    for index, raw in enumerate(descriptors):
        context = f"import descriptor plan {index}"
        require(isinstance(raw, dict), f"{context} must be an object")
        assert isinstance(raw, dict)
        exact_audit_keys(
            raw,
            {
                "header_sha256",
                "dll",
                "original_first_thunk",
                "first_thunk",
                "order",
            },
            context,
        )
        dll = raw.get("dll")
        order = raw.get("order")
        require(
            isinstance(dll, str) and dll.isascii() and bool(dll) and "\0" not in dll,
            f"{context}.dll is invalid",
        )
        assert isinstance(dll, str)
        require(isinstance(order, list), f"{context}.order must be an array")
        assert isinstance(order, list)
        identities: list[tuple[str, str | int]] = []
        for ordinal, identity in enumerate(order):
            where = f"{context}.order[{ordinal}]"
            require(isinstance(identity, dict), f"{where} must be an object")
            assert isinstance(identity, dict)
            exact_audit_keys(identity, {"kind", "value"}, where)
            kind = identity.get("kind")
            item = identity.get("value")
            if kind == "name":
                require(
                    isinstance(item, str) and item.isascii() and bool(item) and "\0" not in item,
                    f"{where} name is invalid",
                )
                assert isinstance(item, str)
            else:
                require(kind == "ordinal", f"{where} kind is unsupported")
                assert kind == "ordinal"
                item = require_exact_int(item, where + ".value", minimum=1, maximum=65535)
            identities.append((kind, item))
        normalized.append(
            {
                "header_sha256": require_sha(raw.get("header_sha256"), context + ".header_sha256"),
                "dll": dll,
                "original_first_thunk": require_exact_int(
                    raw.get("original_first_thunk"),
                    context + ".original_first_thunk",
                    minimum=1,
                    maximum=0xFFFFFFFF,
                ),
                "first_thunk": require_exact_int(
                    raw.get("first_thunk"),
                    context + ".first_thunk",
                    minimum=1,
                    maximum=0xFFFFFFFF,
                ),
                "order": identities,
            }
        )
    return {
        "schema": value["schema"],
        "machine": require_exact_int(value.get("machine"), "machine", minimum=0, maximum=0xFFFF),
        "image_base": require_exact_int(
            value.get("image_base"), "image_base", minimum=0, maximum=0xFFFFFFFF
        ),
        "section_alignment": require_exact_int(
            value.get("section_alignment"), "section_alignment", minimum=1, maximum=0xFFFFFFFF
        ),
        "section_layout_sha256": require_sha(
            value.get("section_layout_sha256"), "section_layout_sha256"
        ),
        "import_directory_rva": require_exact_int(
            value.get("import_directory_rva"), "import_directory_rva", minimum=1, maximum=0xFFFFFFFF
        ),
        "import_directory_size": require_exact_int(
            value.get("import_directory_size"),
            "import_directory_size",
            minimum=40,
            maximum=0xFFFFFFFF,
        ),
        "imports": normalized,
    }


def apply_pe_import_order_candidate(
    candidate: bytes,
    declaration: Mapping[str, object],
) -> tuple[bytes, dict[str, object]]:
    """Apply a locked semantic import order using only candidate thunks."""

    require(isinstance(candidate, bytes), "PE candidate must be immutable bytes")
    require_payload_free_declaration(declaration, "PE import-order declaration")
    plan = _validated_declaration(dict(declaration))
    image = _PE32Imports(candidate)
    require(image.machine == plan["machine"], "PE machine differs from import-order lock")
    require(image.image_base == plan["image_base"], "image base differs from import-order lock")
    require(
        image.section_alignment == plan["section_alignment"]
        and image.layout_digest() == plan["section_layout_sha256"],
        "section layout differs from import-order lock",
    )
    require(
        (image.import_rva, image.import_size)
        == (plan["import_directory_rva"], plan["import_directory_size"]),
        "import data-directory differs from import-order lock",
    )
    descriptors = plan["imports"]
    assert isinstance(descriptors, list)
    require(len(image.imports) == len(descriptors), "import descriptor count differs")

    remap: dict[int, int] = {}
    table_writes: dict[int, int] = {}
    total_slots = 0
    expected_orders = []
    for index, (current, locked) in enumerate(zip(image.imports, descriptors, strict=True)):
        assert isinstance(locked, dict)
        require(
            sha256_bytes(current.raw_descriptor) == locked["header_sha256"],
            f"import descriptor {index} differs from its lock",
        )
        require(
            (current.dll, current.original_first_thunk, current.first_thunk)
            == (locked["dll"], locked["original_first_thunk"], locked["first_thunk"]),
            f"import descriptor {index} identity differs",
        )
        order = locked["order"]
        assert isinstance(order, list)
        current_counts = Counter(entry.identity for entry in current.entries)
        require(current_counts == Counter(order), f"import multiset differs for {current.dll}")
        buckets: defaultdict[tuple[str, str | int], deque[_ImportEntry]] = defaultdict(deque)
        for entry in current.entries:
            buckets[entry.identity].append(entry)
        for destination_index, identity in enumerate(order):
            source_entry = buckets[identity].popleft()
            destination_va = image.image_base + current.first_thunk + destination_index * 4
            require(source_entry.slot_va not in remap, "duplicate source IAT slot")
            remap[source_entry.slot_va] = destination_va
            for table_rva in (current.original_first_thunk, current.first_thunk):
                file_offset = image.rva_to_offset(table_rva + destination_index * 4, 4)
                require(file_offset not in table_writes, "overlapping ILT/IAT write plan")
                table_writes[file_offset] = source_entry.thunk
        require(
            all(not values for values in buckets.values()), "import occurrence was not consumed"
        )
        total_slots += len(current.entries)
        expected_orders.append(tuple(order))
    require(len(remap) == total_slots, "IAT remap lost one or more slots")
    require(len(set(remap.values())) == total_slots, "IAT remap is not one-to-one")
    require(set(remap) == set(remap.values()), "IAT remap is not a slot permutation")
    moved = {old: new for old, new in remap.items() if old != new}

    operand_offsets: set[int] = set()
    if moved:
        relocation_offsets = image.highlow_relocation_offsets()
        import_section = image.section_for_rva(image.import_rva, image.import_size)
        unrelocated = []
        for section in image.sections:
            if section == import_section or section.raw_size < 4:
                continue
            for file_offset in range(section.raw_offset, section.raw_end - 3):
                value = struct.unpack_from("<I", candidate, file_offset)[0]
                if value not in moved:
                    continue
                if file_offset not in relocation_offsets:
                    unrelocated.append(file_offset)
                else:
                    operand_offsets.add(file_offset)
        require(
            not unrelocated,
            f"{len(unrelocated)} IAT-looking DWORD(s) lack HIGHLOW relocations",
        )
        require(
            all(right - left >= 4 for left, right in pairwise(sorted(operand_offsets))),
            "relocated IAT operands overlap",
        )

    output = bytearray(candidate)
    for file_offset, thunk in table_writes.items():
        struct.pack_into("<I", output, file_offset, thunk)
    for file_offset in operand_offsets:
        old_va = struct.unpack_from("<I", output, file_offset)[0]
        struct.pack_into("<I", output, file_offset, remap[old_va])
    result = bytes(output)
    checked = _PE32Imports(result)
    require(
        [tuple(entry.identity for entry in descriptor.entries) for descriptor in checked.imports]
        == expected_orders,
        "post-transform import order verification failed",
    )
    require(
        [Counter(entry.thunk for entry in descriptor.entries) for descriptor in checked.imports]
        == [Counter(entry.thunk for entry in descriptor.entries) for descriptor in image.imports],
        "post-transform candidate thunk preservation failed",
    )
    return result, {
        "schema": plan["schema"],
        "total_slots": total_slots,
        "moved_slots": len(moved),
        "rewritten_operands": len(operand_offsets),
        "input_sha256": sha256_bytes(candidate),
        "output_sha256": sha256_bytes(result),
        "candidate_only": True,
        "oracle_payload_bytes_read": 0,
    }


__all__ = ["apply_pe_import_order_candidate", "capture_pe_import_order"]
