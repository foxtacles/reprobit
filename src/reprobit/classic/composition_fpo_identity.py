"""Classic compiler algorithms: FPO/CodeView mosaic identity and donor-source carriers."""

from __future__ import annotations

import re
import struct
from collections.abc import Callable
from typing import Any, cast

import reprobit.declaration_shapes as entropy_generator
from reprobit.binary import ByteIdentityError, require
from reprobit.coff_format import (
    CoffObject,
    coff_body,
    detailed_relocations,
    section_definitions,
)

from .coff import (
    _coff_table_bytes,
    _comdat_child,
    _comdat_child_closure,
    canonical_counter_receipt_sha256,
    comdat_primary_identity_multiset,
    function_multiset,
    section_shape_receipt_sha256,
)
from .composition_relocations import require_same_semantic_relocations
from .debug import (
    linker_payload_multiset,
    parse_fpo_data,
)
from .foundation import (
    exact_audit_keys,
    exact_json_equal,
    require_exact_int,
    require_sha,
    sha256_bytes,
)
from .ia32 import (
    EH_CLOSURE_CHILDREN,
    ORDINARY_FPO_CLOSURE_CHILDREN,
)


def require_ordinary_fpo_mosaic_identity(
    seed: CoffObject,
    seed_primary: dict[str, Any],
    donor: CoffObject,
    donor_primary: dict[str, Any],
    function: dict[str, Any],
    identity: dict[str, Any],
    context: str,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Authenticate one ordinary mosaic's exact FPO/CodeView closure."""
    return _require_fpo_mosaic_identity(
        seed,
        seed_primary,
        donor,
        donor_primary,
        function,
        identity,
        context,
        source_refactor=False,
    )


def require_ordinary_fpo_self_permutation_receipts(
    seed: CoffObject, donor: CoffObject, function: dict[str, Any], context: str
) -> dict[str, Any]:
    """Pin all object-wide identities for the isolated FPO permutation."""
    return require_self_permutation_receipts(
        seed, donor, function, ORDINARY_FPO_CLOSURE_CHILDREN, context
    )


def require_self_permutation_receipts(
    seed: CoffObject,
    donor: CoffObject,
    function: dict[str, Any],
    closure_children: tuple[str, ...],
    context: str,
) -> dict[str, Any]:
    """Pin all object-wide identities for one isolated self-permutation.

    The permutation exchanges two of the seed's own complete instructions,
    so the donor is a witness rather than a byte source: it must be the same
    translation unit in a different declaration-carrier state, with an
    identical function set, COMDAT identity set, section shape and linker
    payload, and a COMDAT closure that describes the same procedure.
    """
    require(
        closure_children in (ORDINARY_FPO_CLOSURE_CHILDREN, EH_CLOSURE_CHILDREN),
        f"{context}: self-permutation closure class is not supported",
    )
    permutation = function["instruction_self_permutation"]
    seed_functions = function_multiset(seed)
    donor_functions = function_multiset(donor)
    seed_comdats = comdat_primary_identity_multiset(seed)
    donor_comdats = comdat_primary_identity_multiset(donor)
    seed_linker = linker_payload_multiset(seed)
    donor_linker = linker_payload_multiset(donor)
    require(
        seed_functions == donor_functions
        and canonical_counter_receipt_sha256(seed_functions)
        == canonical_counter_receipt_sha256(donor_functions)
        == permutation["expected_function_multiset_sha256"],
        f"{context}: function multiset receipt differs",
    )
    require(
        seed_comdats == donor_comdats
        and canonical_counter_receipt_sha256(seed_comdats)
        == canonical_counter_receipt_sha256(donor_comdats)
        == permutation["expected_comdat_multiset_sha256"],
        f"{context}: COMDAT multiset receipt differs",
    )
    require(
        len(seed.sections) == len(donor.sections)
        and section_shape_receipt_sha256(seed)
        == section_shape_receipt_sha256(donor)
        == permutation["expected_section_shape_sha256"],
        f"{context}: section shape receipt differs",
    )
    require(
        seed_linker == donor_linker
        and sum(seed_linker.values())
        == sum(donor_linker.values())
        == permutation["expected_linker_payload_count"]
        and (
            canonical_counter_receipt_sha256(seed_linker)
            == canonical_counter_receipt_sha256(donor_linker)
            == permutation["expected_linker_payload_sha256"]
        ),
        f"{context}: linker payload receipt differs",
    )
    seed_primary = seed.function_section(function["mangled"])
    donor_primary = donor.function_section(function["mangled"])
    for child_name in closure_children:
        seed_child = _comdat_child(seed, seed_primary, child_name)
        donor_child = _comdat_child(donor, donor_primary, child_name)
        seed_child_body = coff_body(seed, seed_child)
        donor_child_body = coff_body(donor, donor_child)
        if closure_children == EH_CLOSURE_CHILDREN and child_name == ".debug$S":
            require(
                len(seed_child_body) == len(donor_child_body) >= 28
                and seed_child_body[:28] == donor_child_body[:28]
                and (seed_child_body[2:4] == b"\x05\x02"),
                f"{context}: {child_name} procedure identity differs between compiler states",
            )
        else:
            require(
                seed_child_body == donor_child_body,
                f"{context}: {child_name} body differs between compiler states",
            )
    source_identity = function["same_function_source_identity"]
    identifiers = list(
        donor_source_compiler_state_carrier_identifiers(
            source_identity.get("carrier"), f"{context} carrier descriptor"
        )
    )
    normalized_identifiers = source_identity.get("carrier_identifiers")
    require(
        normalized_identifiers is None or normalized_identifiers == identifiers,
        f"{context}: normalized carrier identifier set differs",
    )
    leaked_symbols = [
        symbol["name"]
        for symbol in donor.symbols.values()
        if any(identifier in symbol["name"] for identifier in identifiers)
    ]
    leaked_bytes = [
        identifier for identifier in identifiers if identifier.encode("ascii") in donor.data
    ]
    require(
        not leaked_symbols and (not leaked_bytes),
        f"{context}: generated declarations leaked into donor output",
    )
    return {
        "function_multiset_sha256": permutation["expected_function_multiset_sha256"],
        "comdat_multiset_sha256": permutation["expected_comdat_multiset_sha256"],
        "section_shape_sha256": permutation["expected_section_shape_sha256"],
        "linker_payload_sha256": permutation["expected_linker_payload_sha256"],
        "carrier_identifiers_absent": True,
    }


def require_source_fpo_mosaic_identity(
    seed: CoffObject,
    seed_primary: dict[str, Any],
    donor: CoffObject,
    donor_primary: dict[str, Any],
    function: dict[str, Any],
    identity: dict[str, Any],
    context: str,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Authenticate one source-refactor mosaic's exact FPO closure.

    The seed and donor may have separately pinned CodeView payload sizes and
    bodies, but they must describe the same procedure and retain identical
    FPO data and semantic child relocations. The composed output remains
    seed-authoritative for both children.
    """
    return _require_fpo_mosaic_identity(
        seed,
        seed_primary,
        donor,
        donor_primary,
        function,
        identity,
        context,
        source_refactor=True,
    )


def measure_fpo_mosaic_identity(
    seed: CoffObject,
    seed_primary: dict[str, Any],
    donor: CoffObject,
    donor_primary: dict[str, Any],
    *,
    receipt_prefix: str,
    source_refactor: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Measure the identity and flattened pins consumed by the FPO validator.

    Repair uses this to replay an existing FPO mosaic class against fresh
    compiler objects.  The caller keeps the saved identity class while
    refreshing its object geometry and receipt hashes.
    """

    identity: dict[str, Any] = {
        "kind": (
            "seed_authoritative_source_refactor_fpo_codeview_v1"
            if source_refactor
            else "seed_authoritative_fpo_codeview_v1"
        )
    }
    pins: dict[str, Any] = {}
    seed_definitions = section_definitions(seed)
    for key, name in (("debug_f", ".debug$F"), ("debug_s", ".debug$S")):
        left = _comdat_child(seed, seed_primary, name)
        right = _comdat_child(donor, donor_primary, name)
        definition = seed_definitions[left["number"]]
        geometry = {
            "associated": definition["associated"],
            "characteristics": left["characteristics"],
            "line_count": left["line_count"],
            "relocation_count": left["relocation_count"],
            "section_number": left["number"],
            "selection": definition["selection"],
        }
        if not source_refactor:
            geometry["raw_size"] = left["raw_size"]
        identity[key] = geometry
        for role, coff, section in (("seed", seed, left), ("donor", donor, right)):
            path = f"{receipt_prefix}.{key}"
            pins[f"{path}.expected_{role}_body_sha256"] = sha256_bytes(coff_body(coff, section))
            pins[f"{path}.expected_{role}_relocation_sha256"] = sha256_bytes(
                _coff_table_bytes(coff, section, "relocations")
            )
            if source_refactor:
                pins[f"{path}.expected_{role}_raw_size"] = section["raw_size"]
        if key == "debug_f":
            pins[f"{receipt_prefix}.debug_f.expected_record"] = parse_fpo_data(
                coff_body(seed, left), expected_proc_size=seed_primary["raw_size"]
            )
            continue
        seed_body = coff_body(seed, left)
        donor_body = coff_body(donor, right)
        require(
            len(seed_body) >= 28 and len(donor_body) >= 28,
            "FPO CodeView procedure streams are too short",
        )
        cb_proc, dbg_start, dbg_end = struct.unpack_from("<III", seed_body, 16)
        pins.update(
            {
                f"{receipt_prefix}.debug_s.expected_cb_proc": cb_proc,
                f"{receipt_prefix}.debug_s.expected_dbg_start": dbg_start,
                f"{receipt_prefix}.debug_s.expected_dbg_end": dbg_end,
                f"{receipt_prefix}.debug_s.expected_common_prefix_sha256": sha256_bytes(
                    seed_body[:28]
                ),
                f"{receipt_prefix}.debug_s.expected_record_kind": seed_body[2:4].hex(),
            }
        )
        if source_refactor:
            pins[f"{receipt_prefix}.debug_s.expected_seed_tail_sha256"] = sha256_bytes(
                seed_body[28:]
            )
            pins[f"{receipt_prefix}.debug_s.expected_donor_tail_sha256"] = sha256_bytes(
                donor_body[28:]
            )
            pins[f"{receipt_prefix}.debug_s.expected_extra_relocations"] = [
                {
                    field: row[field]
                    for field in (
                        "addend",
                        "offset",
                        "target",
                        "target_section",
                        "target_storage",
                        "target_type",
                        "target_value",
                        "type",
                        "width",
                    )
                }
                for row in detailed_relocations(seed, left)[2:]
            ]
    pins.update(
        {
            f"{receipt_prefix}.expected_comdat_count": sum(
                comdat_primary_identity_multiset(seed).values()
            ),
            f"{receipt_prefix}.expected_function_count": sum(function_multiset(seed).values()),
            f"{receipt_prefix}.expected_primary_characteristics": seed_primary["characteristics"],
            f"{receipt_prefix}.expected_primary_selection": seed_definitions[
                seed_primary["number"]
            ]["selection"],
            f"{receipt_prefix}.expected_seed_line_sha256": sha256_bytes(
                _coff_table_bytes(seed, seed_primary, "lines")
            ),
            f"{receipt_prefix}.expected_donor_line_sha256": sha256_bytes(
                _coff_table_bytes(donor, donor_primary, "lines")
            ),
        }
    )
    return identity, pins


def _require_fpo_mosaic_identity(
    seed: CoffObject,
    seed_primary: dict[str, Any],
    donor: CoffObject,
    donor_primary: dict[str, Any],
    function: dict[str, Any],
    identity: dict[str, Any],
    context: str,
    *,
    source_refactor: bool,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """The one FPO-closure authentication behind both mosaic flavours.

    A declaration-carrier pair (``source_refactor=False``) is one translation
    unit in two compiler states: the two CodeView payloads share one pinned
    size and the FPO row is compared byte for byte.  A source refactor
    (``source_refactor=True``) pins the seed's and the donor's CodeView sizes
    and tails separately, pins the FPO row by digest as well, and may declare
    extra ``.debug$S`` relocations beyond the procedure's own.  Every other
    obligation, and every message, is the same for both.
    """
    mangled = function["mangled"]
    seed_definitions = section_definitions(seed)
    donor_definitions = section_definitions(donor)
    require(
        seed_primary["characteristics"]
        == donor_primary["characteristics"]
        == identity["expected_primary_characteristics"],
        f"{context}: primary characteristics differ",
    )
    require(
        seed_definitions[seed_primary["number"]]["selection"]
        == donor_definitions[donor_primary["number"]]["selection"]
        == identity["expected_primary_selection"],
        f"{context}: primary COMDAT selection differs",
    )
    for role, coff in (("seed", seed), ("donor", donor)):
        require(
            sum(function_multiset(coff).values()) == identity["expected_function_count"],
            f"{context}: {role} function census differs",
        )
        require(
            sum(comdat_primary_identity_multiset(coff).values())
            == identity["expected_comdat_count"],
            f"{context}: {role} COMDAT census differs",
        )
    require(
        linker_payload_multiset(seed) == linker_payload_multiset(donor),
        f"{context}: source refactor changed linker payload"
        if source_refactor
        else f"{context}: declaration carrier changed linker payload",
    )
    require(
        sha256_bytes(_coff_table_bytes(seed, seed_primary, "lines"))
        == identity["expected_seed_line_sha256"]
        and sha256_bytes(_coff_table_bytes(donor, donor_primary, "lines"))
        == identity["expected_donor_line_sha256"],
        f"{context}: target line-table pin differs",
    )
    require(
        _comdat_child_closure(seed, seed_primary)
        == _comdat_child_closure(donor, donor_primary)
        == (2, (".debug$F", ".debug$S")),
        f"{context}: closure is not the exact FPO pair",
    )
    pairs = []
    for key, name in (("debug_f", ".debug$F"), ("debug_s", ".debug$S")):
        pin = identity[key]
        left = _comdat_child(seed, seed_primary, name)
        right = _comdat_child(donor, donor_primary, name)
        for role, coff, section, definitions, primary in (
            ("seed", seed, left, seed_definitions, seed_primary),
            ("donor", donor, right, donor_definitions, donor_primary),
        ):
            definition = definitions[section["number"]]
            raw_size_key = f"expected_{role}_raw_size" if source_refactor else "raw_size"
            require(
                section["number"] == pin["section_number"]
                and section["raw_size"] == pin[raw_size_key]
                and (section["relocation_count"] == pin["relocation_count"])
                and (section["line_count"] == pin["line_count"])
                and (section["characteristics"] == pin["characteristics"])
                and (definition["selection"] == pin["selection"])
                and (definition["associated"] == pin["associated"])
                and (not source_refactor or definition["associated"] == primary["number"]),
                f"{context}: {role} {name} geometry differs",
            )
            require(
                sha256_bytes(coff_body(coff, section)) == pin[f"expected_{role}_body_sha256"],
                f"{context}: {role} {name} body pin differs",
            )
            require(
                sha256_bytes(_coff_table_bytes(coff, section, "relocations"))
                == pin[f"expected_{role}_relocation_sha256"],
                f"{context}: {role} {name} relocation-table pin differs",
            )
        require_same_semantic_relocations(seed, left, donor, right, f"{context} {name}")
        expected_rows = [(0, 4, 7)] if name == ".debug$F" else [(28, 4, 11), (32, 2, 10)]
        expected_extra = (
            pin.get("expected_extra_relocations", [])
            if source_refactor and name == ".debug$S"
            else []
        )
        for role, coff, section, primary in (
            ("seed", seed, left, seed_primary),
            ("donor", donor, right, donor_primary),
        ):
            rows = detailed_relocations(coff, section)
            # A declaration-carrier pair names the seed's seat from both
            # children; a source refactor names each object's own.
            target_section = (primary if source_refactor else seed_primary)["number"]
            require(
                len(rows) == len(expected_rows) + len(expected_extra)
                and all(
                    (
                        (row["offset"], row["width"], row["type"]) == expected
                        and row["addend"] == 0
                        and (row["target"] == mangled)
                        and (row["target_section"] == target_section)
                        and (row["target_value"] == 0)
                        and (row["target_type"] == 32)
                        and (row["target_storage"] == 2)
                        # The rows may carry the pinned extra relocations
                        # after the procedure's own; those are checked next.
                        for row, expected in zip(rows, expected_rows, strict=False)
                    )
                ),
                f"{context}: {role} {name} semantic relocations differ",
            )
            if source_refactor:
                require(
                    all(
                        (
                            all(
                                (
                                    row[field] == expected[field]
                                    for field in (
                                        "offset",
                                        "width",
                                        "type",
                                        "addend",
                                        "target",
                                        "target_section",
                                        "target_value",
                                        "target_type",
                                        "target_storage",
                                    )
                                )
                            )
                            for row, expected in zip(
                                rows[len(expected_rows) :], expected_extra, strict=True
                            )
                        )
                    ),
                    f"{context}: {role} {name} extra semantic relocations differ",
                )
        pairs.append((left, right))
    seed_f = coff_body(seed, pairs[0][0])
    donor_f = coff_body(donor, pairs[0][1])
    if source_refactor:
        fpo_pin = identity["debug_f"]["expected_record"]
        require(
            seed_f == donor_f and sha256_bytes(seed_f) == fpo_pin["raw_sha256"],
            f"{context}: FPO raw bytes differ",
        )
    else:
        require(seed_f == donor_f, f"{context}: FPO raw bytes differ between compiler states")
        fpo_pin = identity["debug_f"]["expected_record"]
    require(
        exact_json_equal(
            parse_fpo_data(seed_f, expected_proc_size=seed_primary["raw_size"]), fpo_pin
        )
        and exact_json_equal(
            parse_fpo_data(donor_f, expected_proc_size=donor_primary["raw_size"]), fpo_pin
        ),
        f"{context}: parsed FPO record differs",
    )
    seed_s = coff_body(seed, pairs[1][0])
    donor_s = coff_body(donor, pairs[1][1])
    debug_pin = identity["debug_s"]
    require(
        (
            len(seed_s) == debug_pin["expected_seed_raw_size"]
            and len(donor_s) == debug_pin["expected_donor_raw_size"]
            if source_refactor
            else len(seed_s) == len(donor_s) == debug_pin["raw_size"]
        )
        and seed_s[:28] == donor_s[:28]
        and (sha256_bytes(seed_s[:28]) == debug_pin["expected_common_prefix_sha256"])
        and (seed_s[2:4].hex() == debug_pin["expected_record_kind"])
        and (
            not source_refactor
            or (
                sha256_bytes(seed_s[28:]) == debug_pin["expected_seed_tail_sha256"]
                and sha256_bytes(donor_s[28:]) == debug_pin["expected_donor_tail_sha256"]
            )
        ),
        f"{context}: CodeView procedure identity differs",
    )
    for role, raw in (("seed", seed_s), ("donor", donor_s)):
        cb_proc, dbg_start, dbg_end = struct.unpack_from("<III", raw, 16)
        require(
            (cb_proc, dbg_start, dbg_end)
            == (
                debug_pin["expected_cb_proc"],
                debug_pin["expected_dbg_start"],
                debug_pin["expected_dbg_end"],
            )
            and 0 <= dbg_start <= dbg_end < cb_proc,
            f"{context}: {role} CodeView procedure range differs",
        )
    return pairs


DONOR_SOURCE_CARRIER_SEATS = {
    "extern_run_pair_v1": ("after_includes_and_eof_v1", ("header", "seat")),
    "declaration_run_triple_v1": ("start_after_includes_and_eof_v1", ("pre", "post", "eof")),
}
DONOR_SOURCE_FORCE_INCLUDE_CARRIERS = {
    "force_included_shape_v1": ("force_include_v1", "generate_shape", ("classes", "functions")),
    "force_included_pad_shape_v1": (
        "force_include_v1",
        "generate_pad_shape",
        ("classes", "functions_per_class"),
    ),
}


def _donor_source_force_included_shape(kind: str, params: dict[str, Any]) -> bytes:
    """Render one force-included carrier's declaration-only shape."""
    _, generator_name, names = DONOR_SOURCE_FORCE_INCLUDE_CARRIERS[kind]
    generator: Callable[..., str] = getattr(entropy_generator, generator_name)
    return generator(*(params[name] for name in names)).encode("ascii")


def donor_source_compiler_state_carrier_identifiers(value: object, context: str) -> tuple[str, ...]:
    """Return the deterministic declaration identifiers for one validated carrier."""

    carrier = validate_donor_source_compiler_state_carrier(value, context)
    kind = cast(str, carrier["kind"])
    if kind in DONOR_SOURCE_FORCE_INCLUDE_CARRIERS:
        generated = _donor_source_force_included_shape(kind, carrier)
        return tuple(
            dict.fromkeys(
                match.group(1).decode("ascii")
                for match in re.finditer(
                    rb"(?:\bclass\s+|\bextern\s+int\s+|\bvoid\s+)"
                    rb"([A-Za-z_][A-Za-z0-9_]*)",
                    generated,
                )
            )
        )
    placement, roles = DONOR_SOURCE_CARRIER_SEATS[kind]
    assert carrier["placement"] == placement
    width = cast(int, carrier["width"])
    return tuple(
        f"{carrier[f'{role}_prefix']}{index:0{width}d}"
        for role in roles
        for index in range(cast(int, carrier[f"{role}_count"]))
    )


def validate_donor_source_compiler_state_carrier(value: object, context: str) -> dict[str, Any]:
    """Validate one closed, declaration-only multi-seat source carrier.

    Two grammars are admitted, both already part of the mosaic carrier
    vocabulary and both emitting nothing at all: the two-seat extern run
    (declarations of never-defined objects, after the include block and at
    physical EOF) and the three-seat forward-declaration run (bare class
    declarations at file start, after the include block, and at EOF).  Every
    obligation -- per-seat count bounds, identity non-collision, and the
    exact generated-declaration digest -- applies to both.
    """
    require(isinstance(value, dict), f"{context} must be an object")
    document = cast(dict[str, Any], value)
    kind = document.get("kind")
    if kind in DONOR_SOURCE_FORCE_INCLUDE_CARRIERS:
        placement, _, names = DONOR_SOURCE_FORCE_INCLUDE_CARRIERS[kind]
        exact_audit_keys(
            document, {"kind", "placement", "generated_declarations_sha256", *names}, context
        )
        require(document.get("placement") == placement, f"{context} kind or placement differs")
        params = {
            name: require_exact_int(
                document.get(name), f"{context}.{name}", minimum=1, maximum=4096
            )
            for name in names
        }
        try:
            generated = _donor_source_force_included_shape(kind, params)
        except ValueError as error:
            raise ByteIdentityError(f"{context} declaration shape is invalid: {error}") from error
        require(
            require_sha(
                document.get("generated_declarations_sha256"),
                context + ".generated_declarations_sha256",
            )
            == sha256_bytes(generated),
            f"{context} generated declarations differ from their pin",
        )
        return {
            "kind": kind,
            "placement": placement,
            **params,
            "generated_declarations_sha256": sha256_bytes(generated),
        }
    require(kind in DONOR_SOURCE_CARRIER_SEATS, f"{context} kind or placement differs")
    placement, roles = DONOR_SOURCE_CARRIER_SEATS[cast(str, kind)]
    keys = {"kind", "placement", "width", "generated_declarations_sha256"}
    for role in roles:
        keys |= {f"{role}_prefix", f"{role}_count"}
    exact_audit_keys(document, keys, context)
    require(document.get("placement") == placement, f"{context} kind or placement differs")
    width = require_exact_int(document.get("width"), context + ".width", minimum=1, maximum=3)
    generator = (
        entropy_generator.generate_extern_run
        if kind == "extern_run_pair_v1"
        else entropy_generator.generate_forward_run
    )
    counts = {}
    payloads = []
    identities: set[str] = set()
    for role in roles:
        prefix = document.get(f"{role}_prefix")
        count = require_exact_int(
            document.get(f"{role}_count"), context + f".{role}_count", minimum=1, maximum=999
        )
        require(isinstance(prefix, str), f"{context}.{role}_prefix differs")
        try:
            payload = generator(cast(str, prefix), count, width).encode("ascii")
        except ValueError as error:
            raise ByteIdentityError(
                f"{context}.{role} declaration run is invalid: {error}"
            ) from error
        run_names = {f"{prefix}{index:0{width}d}" for index in range(count)}
        require(
            len(run_names) == count and (not identities.intersection(run_names)),
            f"{context} declaration identities collide",
        )
        identities.update(run_names)
        payloads.append(payload)
        counts[role] = (prefix, count)
    generated = b"".join(payloads)
    require(
        require_sha(
            document.get("generated_declarations_sha256"),
            context + ".generated_declarations_sha256",
        )
        == sha256_bytes(generated),
        f"{context} generated declarations differ from their pin",
    )
    normalized = {
        "kind": kind,
        "placement": placement,
        "width": width,
        "generated_declarations_sha256": sha256_bytes(generated),
    }
    for role in roles:
        normalized[f"{role}_prefix"] = counts[role][0]
        normalized[f"{role}_count"] = counts[role][1]
    return normalized
