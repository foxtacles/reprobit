"""Shared skeleton of the retail-exact candidate producers.

Every candidate producer -- instruction schedule, web recolour, register
bijection and its re-encoding, relational form, composed and donor rewriting
-- opens the same seats before it does anything class-specific: it parses
the seed and donor objects, finds the target COMDAT in each, and requires
the declaration's seat, section-count, function and COMDAT census,
header/count, selection, closure, metadata and body pins.  Afterwards each
finishes the same way: the linked length is pinned, the relocation
semantics are derived, the image is installed through an equal-body or
same-slot delegate, the composed object is checked against the image and
the seed, and the proof is assembled.

This module holds those shared phases.  A producer describes its class once
in a :class:`CandidateRecipe`; the phases then reproduce that producer's
own refusal messages byte for byte.  The label prefixes every message, and
the classes whose messages depart from the common form -- a *witness*
rather than a donor, measured values appended to a message, a closure check
merged into one requirement, a declared donor seat with its own message --
say so in their recipe rather than re-writing the phase.  Nothing here
decides what a class proves: the transformation, its own declaration
checks and its table bookkeeping stay in the producer.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Literal

from reprobit.binary import require
from reprobit.coff_format import (
    CoffObject,
    CoffSection,
    Relocation,
    coff_body,
    section_definitions,
)

from .coff import (
    _comdat_child,
    _comdat_child_closure,
    comdat_primary_identity_multiset,
    function_multiset,
)
from .composition import compose_equal_body_comdat
from .composition_mosaic import instruction_mosaic_metadata_sha256
from .composition_same_slot import compose_same_slot_resize
from .foundation import require_payload_free_declaration, sha256_bytes
from .ia32 import require_declared_relocation_semantics


@dataclass(frozen=True, slots=True)
class CandidateRecipe:
    """How one candidate class opens its seats.

    ``label`` prefixes every message (``"web-recolour"``); ``splice_class``
    is the declaration's class name; ``spec_key`` names the class-specific
    sub-declaration; ``admissible_closures`` lists the COMDAT child closures
    for which an installation delegate exists.  The remaining fields record
    where a class departs from the common form and default to it:

    - ``declaration_label`` / ``source_refactor_label`` replace the label in
      the payload-free and source-refactor messages only.
    - ``kind`` requires ``spec["kind"]`` to equal a value, with the message
      to use, right after the spec is read.
    - ``donor_seat`` says whether the donor's target section must sit where
      the seed's does (``shared``), where ``expected_donor_section_number``
      declares (``declared``), or either depending on whether that pin is
      present (``optional``); ``declared_seat_message`` replaces the seat
      message in the declared branch of the optional form.
    - ``donor_section_count`` says the same for the global section count.
    - ``census`` is ``equal`` when the donor must carry exactly the seed's
      function and COMDAT multisets, ``extras`` when it may carry the extra
      functions ``expected_donor_extra_functions`` declares, one each.
    - ``witness_word`` is the noun the census and body messages use for the
      donor.
    - ``length_pins`` names the (seed, donor) body-length pins when the two
      bodies are pinned separately; ``None`` pins both to
      ``expected_body_length``.
    - ``closure_message`` merges the closure-identity and closure-admissible
      checks into one requirement with that message.
    - ``verbose`` appends the measured values to the seat, count, census,
      header, selection, closure, metadata and body messages.
    """

    label: str
    splice_class: str
    spec_key: str
    admissible_closures: tuple[tuple[str, ...], ...]
    declaration_label: str | None = None
    source_refactor_label: str | None = None
    kind: tuple[str, str] | None = None
    donor_seat: Literal["shared", "declared", "optional"] = "shared"
    declared_seat_message: str | None = None
    donor_section_count: Literal["shared", "declared", "optional"] = "shared"
    census: Literal["equal", "extras"] = "equal"
    witness_word: str = "donor"
    length_pins: tuple[str, str] | None = None
    closure_message: str | None = None
    verbose: bool = False


@dataclass(frozen=True, slots=True)
class CandidateSeats:
    """The two parsed objects and the target COMDAT seated in each."""

    seed: CoffObject
    donor: CoffObject
    mangled: str
    seed_section: CoffSection
    donor_section: CoffSection
    spec: dict[str, Any]
    expected_closure: tuple[str, ...]


def _message(recipe: CandidateRecipe, text: str, detail: Callable[[], str]) -> str:
    """The message for one check: the label, the text, and (verbose only) the measured values."""
    return f"{recipe.label} {text}{detail()}" if recipe.verbose else f"{recipe.label} {text}"


def open_candidate_seats(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict[str, Any],
    recipe: CandidateRecipe,
) -> CandidateSeats:
    """Parse both objects and require every seat pin of the declaration.

    The checks run in the order every producer ran them: the declaration is
    payload-free, names the class and no source refactor, its spec has the
    declared kind; the target section is seated, the section counts agree,
    the function and COMDAT censuses agree, the header/count pins hold, the
    COMDAT selection and child closure match and the closure admits a
    delegate.  Metadata and body pins follow in
    :func:`pin_candidate_bodies`, after the producer has named its delegate.
    """
    label = recipe.label
    require_payload_free_declaration(function, f"{recipe.declaration_label or label} declaration")
    require(
        function.get("splice_class") == recipe.splice_class,
        f"splice class is not {recipe.splice_class}",
    )
    require(
        "target_source_refactor" not in function,
        f"{recipe.source_refactor_label or label} functions carry no source refactor",
    )
    spec = function[recipe.spec_key]
    if recipe.kind is not None:
        expected_kind, kind_message = recipe.kind
        require(spec["kind"] == expected_kind, kind_message)
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    seat_message = _message(
        recipe,
        "target section seat changed",
        lambda: f": seed {sp['number']} donor {dp['number']}",
    )
    if recipe.donor_seat == "shared":
        require(sp["number"] == dp["number"] == function["expected_section_number"], seat_message)
    elif recipe.donor_seat == "declared":
        require(
            sp["number"] == function["expected_section_number"]
            and dp["number"] == function["expected_donor_section_number"],
            seat_message,
        )
    else:
        donor_seat = function.get("expected_donor_section_number")
        if donor_seat is None:
            require(
                sp["number"] == dp["number"] == function["expected_section_number"], seat_message
            )
        else:
            require(
                sp["number"] == function["expected_section_number"] and dp["number"] == donor_seat,
                recipe.declared_seat_message or seat_message,
            )
    count_message = _message(
        recipe,
        "global section count changed",
        lambda: f": seed {len(seed.sections)} donor {len(donor.sections)}",
    )
    if recipe.donor_section_count == "shared":
        require(
            len(seed.sections) == len(donor.sections) == function["expected_section_count"],
            count_message,
        )
    elif recipe.donor_section_count == "declared":
        require(
            len(seed.sections) == function["expected_section_count"]
            and len(donor.sections) == function["expected_donor_section_count"],
            count_message,
        )
    else:
        require(
            len(seed.sections) == function["expected_section_count"]
            and len(donor.sections)
            == function.get("expected_donor_section_count", function["expected_section_count"]),
            count_message,
        )
    _require_census(seed, donor, function, recipe)
    if recipe.length_pins is None:
        lengths_pinned = sp["raw_size"] == dp["raw_size"] == function["expected_body_length"]
    else:
        seed_key, donor_key = recipe.length_pins
        lengths_pinned = (
            sp["raw_size"] == function[seed_key] and dp["raw_size"] == function[donor_key]
        )
    require(
        lengths_pinned
        and sp["relocation_count"]
        == dp["relocation_count"]
        == function["expected_relocation_count"]
        and (sp["line_count"] == function["expected_seed_line_count"])
        and (dp["line_count"] == function["expected_donor_line_count"])
        and (sp["name"] == dp["name"])
        and (
            sp["characteristics"] == dp["characteristics"] == function["expected_characteristics"]
        ),
        _message(
            recipe,
            "target header/count pins changed",
            lambda: (
                f": raw {sp['raw_size']}/{dp['raw_size']}"
                f" relocations {sp['relocation_count']}/{dp['relocation_count']}"
                f" lines {sp['line_count']}/{dp['line_count']}"
                f" characteristics {sp['characteristics']}/{dp['characteristics']}"
            ),
        ),
    )
    require(
        section_definitions(seed)[sp["number"]]["selection"]
        == section_definitions(donor)[dp["number"]]["selection"]
        == function["expected_selection"],
        _message(
            recipe,
            "COMDAT selection changed",
            lambda: f": {section_definitions(seed)[sp['number']]['selection']}",
        ),
    )
    expected_closure = tuple(function["expected_closure"])
    closure_pinned = (
        _comdat_child_closure(seed, sp)
        == _comdat_child_closure(donor, dp)
        == (len(expected_closure), expected_closure)
    )
    admissible = [list(item) for item in recipe.admissible_closures]
    if recipe.closure_message is None:
        require(
            closure_pinned,
            _message(
                recipe,
                "target closure changed",
                lambda: (
                    f": seed {_comdat_child_closure(seed, sp)}"
                    f" donor {_comdat_child_closure(donor, dp)}"
                ),
            ),
        )
        require(
            list(expected_closure) in admissible,
            f"{label} closure pin names no installation delegate",
        )
    else:
        require(closure_pinned and list(expected_closure) in admissible, recipe.closure_message)
    return CandidateSeats(seed, donor, mangled, sp, dp, spec, expected_closure)


def _require_census(
    seed: CoffObject, donor: CoffObject, function: dict[str, Any], recipe: CandidateRecipe
) -> None:
    label, witness = recipe.label, recipe.witness_word
    seed_functions = function_multiset(seed)
    donor_functions = function_multiset(donor)
    if recipe.census == "equal":
        require(
            seed_functions == donor_functions
            and sum(seed_functions.values()) == function["expected_function_count"],
            _message(
                recipe,
                f"{witness} function set differs",
                lambda: f": {sum(seed_functions.values())} vs {sum(donor_functions.values())}",
            ),
        )
        seed_comdats = comdat_primary_identity_multiset(seed)
        donor_comdats = comdat_primary_identity_multiset(donor)
        require(
            seed_comdats == donor_comdats
            and sum(seed_comdats.values()) == function["expected_comdat_count"],
            _message(
                recipe,
                f"{witness} COMDAT identity set differs",
                lambda: f": {sum(seed_comdats.values())} vs {sum(donor_comdats.values())}",
            ),
        )
        return
    extras = sorted(function.get("expected_donor_extra_functions") or [])
    measured_extra = []
    for name in set(seed_functions) | set(donor_functions):
        left = seed_functions.get(name, 0)
        right = donor_functions.get(name, 0)
        if right == left:
            continue
        require(right == left + 1, f"{label} {witness} function census diverges at {name}")
        measured_extra.append(name)
    require(
        sorted(measured_extra) == extras
        and sum(seed_functions.values()) == function["expected_function_count"],
        f"{label} {witness} function set differs from its declared extras",
    )
    seed_comdats = comdat_primary_identity_multiset(seed)
    donor_comdats = comdat_primary_identity_multiset(donor)
    extra_heads = []
    for key in set(seed_comdats) | set(donor_comdats):
        left = seed_comdats.get(key, 0)
        right = donor_comdats.get(key, 0)
        if right == left:
            continue
        require(right == left + 1, f"{label} {witness} COMDAT census diverges at {key}")
        extra_heads.append(key[0])
    require(
        sorted(extra_heads) == extras
        and sum(seed_comdats.values()) == function["expected_comdat_count"],
        f"{label} {witness} COMDAT identity set differs from its declared extras",
    )


def pin_candidate_bodies(
    seats: CandidateSeats, function: dict[str, Any], recipe: CandidateRecipe
) -> tuple[bytes, bytes]:
    """Require the metadata and body digests and return both bodies."""
    seed, donor, sp, dp = seats.seed, seats.donor, seats.seed_section, seats.donor_section
    require(
        instruction_mosaic_metadata_sha256(seed, sp) == function["expected_seed_metadata_sha256"]
        and instruction_mosaic_metadata_sha256(donor, dp)
        == function["expected_donor_metadata_sha256"],
        _message(
            recipe,
            "metadata differs from its pin",
            lambda: (
                f": seed {instruction_mosaic_metadata_sha256(seed, sp)}"
                f" donor {instruction_mosaic_metadata_sha256(donor, dp)}"
            ),
        ),
    )
    seed_body = coff_body(seed, sp)
    donor_body = coff_body(donor, dp)
    require(
        sha256_bytes(seed_body) == function["expected_seed_body_sha256"]
        and sha256_bytes(donor_body) == function["expected_donor_body_sha256"],
        _message(
            recipe,
            f"seed/{recipe.witness_word} body differs from its pin",
            lambda: (
                f": seed {sha256_bytes(seed_body)} {recipe.witness_word} {sha256_bytes(donor_body)}"
            ),
        ),
    )
    return seed_body, donor_body


def relocated_byte_offsets(rows: Iterable[Relocation]) -> frozenset[int]:
    """Every body byte a relocation record covers."""
    return frozenset(row["offset"] + byte for row in rows for byte in range(row["width"]))


def relocation_symbol_map(rows: Iterable[Relocation]) -> dict[int, dict[str, Any]]:
    """Width and target of each relocation, keyed by its body offset."""
    return {row["offset"]: {"width": row["width"], "target": row["target"]} for row in rows}


def internal_relocation_targets(rows: Iterable[Relocation], section_number: int) -> frozenset[int]:
    """Offsets inside the section that its own relocations point at."""
    return frozenset(row["target_value"] for row in rows if row["target_section"] == section_number)


def require_declared_internal_targets(
    spec: dict[str, Any], internal_targets: frozenset[int], label: str
) -> None:
    """Require the measured in-body target set to equal the declared one, if declared."""
    declared_targets = spec.get("expected_internal_relocation_targets")
    if declared_targets is not None:
        require(
            sorted(internal_targets) == declared_targets,
            f"{label} in-body relocated target set changed",
        )


def require_pinned_length(function: dict[str, Any], image: bytes, label: str) -> None:
    """Require the image to be exactly as long as the retail oracle pin says."""
    pinned_length = function["retail_oracle"]["length"]
    require(pinned_length == len(image), f"{label} linked length changed")


def candidate_relocation_semantics(
    rows: list[Relocation], function: dict[str, Any], label: str
) -> dict[str, Any]:
    """Derive the declared relocation semantics of the installed rows."""
    return require_declared_relocation_semantics(
        rows, function["retail_relocations"], f"{label} candidate relocation semantics"
    )


def equal_body_effective(
    function: dict[str, Any], mangled: str, delegate: str, *, declared_renames: bool
) -> dict[str, Any]:
    """The effective declaration handed to the equal-body delegate.

    The structural-local delegate proves the declared code and xdata renames
    when ``declared_renames`` is set and an empty rename set otherwise (the
    classes that install the seed's own tables); the relocation-layout
    delegate proves the declared relocation moves.
    """
    effective = {
        "mangled": mangled,
        "splice_class": delegate,
        "expected_body_length": function["expected_body_length"],
        "expected_body_sha256": function["expected_body_sha256"],
        "expected_changed_offsets": function["expected_changed_offsets"],
    }
    if delegate == "equal_body_eh_structural_local":
        effective["expected_code_renames"] = (
            function["expected_code_renames"] if declared_renames else []
        )
        effective["expected_xdata_rename_offsets"] = (
            function["expected_xdata_rename_offsets"] if declared_renames else []
        )
    elif delegate == "equal_body_eh_reloc_layout":
        effective["expected_relocation_moves"] = function["expected_relocation_moves"]
        effective["expected_xdata_rename_offsets"] = function["expected_xdata_rename_offsets"]
    return effective


def same_slot_effective(function: dict[str, Any], mangled: str) -> dict[str, Any]:
    """The effective declaration handed to the same-slot resize delegate."""
    return {
        "mangled": mangled,
        "splice_class": "retail_exact_reloc_divergent",
        "expected_seed_length": function["expected_seed_length"],
        "expected_donor_length": function["expected_donor_length"],
        "expected_linked_span": function["expected_linked_span"],
        "expected_body_sha256": function["expected_body_sha256"],
        "expected_seed_line_count": function["expected_seed_line_count"],
        "expected_donor_line_count": function["expected_donor_line_count"],
        "retail_oracle": function["retail_oracle"],
        "retail_relocations": function["retail_relocations"],
    }


def install_equal_body(
    base_bytes: bytes,
    derived: bytes,
    effective: dict[str, Any],
    mangled: str,
    image: bytes,
    label: str,
) -> tuple[bytes, dict[str, Any], CoffObject, CoffSection]:
    """Install ``derived``'s body into ``base_bytes`` and re-read the result."""
    composed, detail = compose_equal_body_comdat(base_bytes, derived, effective)
    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(coff_body(checked, cp) == image, f"{label} composed body differs from the image")
    return composed, detail, checked, cp


def install_same_slot(
    seed_bytes: bytes,
    derived: bytes,
    effective: dict[str, Any],
    mangled: str,
    image: bytes,
    label: str,
    *,
    declared_donor_extras: list[str] | None = None,
) -> tuple[bytes, dict[str, Any], CoffObject, CoffSection]:
    """Install ``derived``'s resized body into the seed and re-read the result."""
    composed, detail = compose_same_slot_resize(
        seed_bytes, derived, effective, declared_donor_extras=declared_donor_extras
    )
    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(coff_body(checked, cp) == image, f"{label} composed body differs from the image")
    return composed, detail, checked, cp


def require_closure_children_unchanged(
    seats: CandidateSeats,
    checked: CoffObject,
    checked_section: CoffSection,
    label: str,
    *,
    skip: tuple[str, ...] = (),
) -> None:
    """Require every closure child the producer did not rewrite to equal the seed's."""
    for child_name in seats.expected_closure:
        if child_name in skip:
            continue
        require(
            coff_body(checked, _comdat_child(checked, checked_section, child_name))
            == coff_body(seats.seed, _comdat_child(seats.seed, seats.seed_section, child_name)),
            f"{label} output changed its {child_name} child",
        )


def comdat_body_range(section: CoffSection) -> set[int]:
    """The file offsets of one section's raw body."""
    return set(range(section["raw_offset"], section["raw_offset"] + section["raw_size"]))


def require_changes_within(
    seed_bytes: bytes, composed: bytes, allowed: set[int], label: str
) -> None:
    """Require every byte that differs from the seed to lie in ``allowed``."""
    require(
        {index for index in range(len(seed_bytes)) if seed_bytes[index] != composed[index]}
        <= allowed,
        f"{label} changed bytes outside its own COMDAT",
    )


def candidate_proof(
    detail: dict[str, Any],
    splice_class: str,
    class_fields: dict[str, Any],
    semantic_detail: dict[str, Any],
) -> dict[str, Any]:
    """Assemble the proof: delegate detail, the class, its fields, the candidate mark, semantics."""
    return {
        **detail,
        "splice_class": splice_class,
        **class_fields,
        "candidate_only": True,
        **semantic_detail,
    }
