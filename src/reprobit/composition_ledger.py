"""Composed-body ledger: what every linker-selected function looked like when verified.

A successful cold verify captures the linker's live public/provider map and
reads the selected object bodies.  The census uses that inventory to distinguish
changed live functions from discarded COMDATs and unselected archive members.

The ledger is derived data.  It never certifies anything: verification always
recompiles and compares whole images.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Literal

from pydantic import Field

from reprobit.atomic_io import write_bytes_atomic
from reprobit.coff_format import CoffObject, coff_body
from reprobit.model import StrictModel
from reprobit.strict_json import canonical_json, strict_load

LEDGER_SCHEMA_VERSION: Literal[2] = 2
COMPOSED_BODY_LEDGER_RELATIVE = ("ledger", "composed-bodies.json")
_IMAGE_SCN_CNT_CODE = 0x20


class LedgerFunction(StrictModel):
    """One linker-selected function body as verified."""

    provider: str
    translation_unit_id: str | None = None
    body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    body_length: int = Field(ge=0)


class ComposedTargetLedger(StrictModel):
    functions: dict[str, LedgerFunction] = Field(default_factory=dict)


class ComposedBodyLedger(StrictModel):
    schema_version: Literal[2] = LEDGER_SCHEMA_VERSION
    graph_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    targets: dict[str, ComposedTargetLedger] = Field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class FunctionBody:
    sha256: str
    length: int


@dataclass(frozen=True, slots=True)
class ProvidedObject:
    """One positional linker input: its reference, owning unit (if any) and function bodies."""

    provider: str
    bodies: Mapping[str, FunctionBody]
    translation_unit_id: str | None = None


@dataclass(frozen=True, slots=True)
class UnrecordedFallout:
    """A selected, unrecorded function whose fresh seed body differs from the ledger."""

    translation_unit_id: str
    symbol: str
    verified_body_sha256: str
    verified_body_length: int
    fresh_body_sha256: str


def function_bodies(data: bytes) -> dict[str, FunctionBody]:
    """External code symbols that begin a non-empty code section, with their body digests.

    Every MSVC ``/Gy`` function is such a symbol in its own COMDAT; a plain
    ``.text`` section owned by one function qualifies the same way.  Static
    functions never take part in linker selection and are left out.
    """

    coff = CoffObject(data)
    bodies: dict[str, FunctionBody] = {}
    for symbol in coff.symbols.values():
        if (
            symbol["storage"] != 2
            or symbol["value"] != 0
            or not 0 < symbol["section"] <= len(coff.sections)
        ):
            continue
        section = coff.sections[symbol["section"] - 1]
        if not (section["characteristics"] & _IMAGE_SCN_CNT_CODE) or section["raw_size"] <= 0:
            continue
        body = bytes(coff_body(coff, section))
        bodies[symbol["name"]] = FunctionBody(sha256(body).hexdigest(), len(body))
    return bodies


def select_providers(
    objects: Sequence[ProvidedObject], live_providers: Mapping[str, str]
) -> dict[str, LedgerFunction]:
    """Read only the bodies of providers named by the actual linker's live map."""

    by_reference = {item.provider: item for item in objects}
    if len(by_reference) != len(objects):
        raise ValueError("linker input inventory repeats an object")
    selected: dict[str, LedgerFunction] = {}
    for symbol, reference in live_providers.items():
        item = by_reference[reference]
        body = item.bodies.get(symbol)
        if body is None:
            continue  # Static/section-interior symbols are outside this census.
        selected[symbol] = LedgerFunction(
            provider=item.provider,
            translation_unit_id=item.translation_unit_id,
            body_sha256=body.sha256,
            body_length=body.length,
        )
    return selected


def build_ledger(
    graph_digest: str,
    targets: Mapping[str, Sequence[ProvidedObject]],
    live_providers: Mapping[str, Mapping[str, str]],
) -> ComposedBodyLedger:
    return ComposedBodyLedger(
        graph_digest=graph_digest,
        targets={
            target_id: ComposedTargetLedger(
                functions=dict(sorted(select_providers(objects, live_providers[target_id]).items()))
            )
            for target_id, objects in sorted(targets.items())
        },
    )


def census_unrecorded_fallout(
    target: ComposedTargetLedger,
    fresh: Mapping[str, Mapping[str, FunctionBody]],
    recorded: Mapping[str, Collection[str]],
) -> tuple[UnrecordedFallout, ...]:
    """Selected functions of the given units whose fresh seed body left its verified body.

    ``fresh`` maps translation-unit ids to their fresh seed bodies; ``recorded``
    maps unit ids to the function symbols that already carry a saved record
    there.  Recorded functions are the repair's business; functions the linker
    takes from another object cannot change this image and are ignored.
    """

    fallout: list[UnrecordedFallout] = []
    for unit_id, bodies in sorted(fresh.items()):
        known = set(recorded.get(unit_id, ()))
        for symbol, body in sorted(bodies.items()):
            verified = target.functions.get(symbol)
            if (
                verified is None
                or verified.translation_unit_id != unit_id
                or symbol in known
                or verified.body_sha256 == body.sha256
            ):
                continue
            fallout.append(
                UnrecordedFallout(
                    unit_id, symbol, verified.body_sha256, verified.body_length, body.sha256
                )
            )
    return tuple(fallout)


def canonical_ledger_payload(ledger: ComposedBodyLedger) -> bytes:
    """Return the one canonical byte representation used for repair evidence."""

    return canonical_json(ledger.model_dump(mode="json"))


def write_ledger(path: Path, ledger: ComposedBodyLedger) -> bytes:
    """Write and return the exact canonical ledger payload."""

    payload = canonical_ledger_payload(ledger)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_bytes_atomic(path, payload)
    return payload


class ObsoleteLedgerError(ValueError):
    """An older approximate ledger needs replacement by a successful cold verify."""


def read_ledger(path: Path) -> ComposedBodyLedger:
    value = strict_load(path)
    if (
        isinstance(value, dict)
        and type(value.get("schema_version")) is int
        and value["schema_version"] == 1
    ):
        # Validate the old shape before treating it as obsolete, rather than
        # hiding malformed persisted data as an ordinary upgrade.
        ComposedBodyLedger.model_validate({**value, "schema_version": LEDGER_SCHEMA_VERSION})
        raise ObsoleteLedgerError(
            "saved repair data predates live linker maps; run rbit verify to refresh it"
        )
    return ComposedBodyLedger.model_validate(value)


def ledger_translation_units(ledger: ComposedBodyLedger) -> Iterable[str]:
    for target in ledger.targets.values():
        for function in target.functions.values():
            if function.translation_unit_id is not None:
                yield function.translation_unit_id


__all__ = [
    "COMPOSED_BODY_LEDGER_RELATIVE",
    "LEDGER_SCHEMA_VERSION",
    "ComposedBodyLedger",
    "ComposedTargetLedger",
    "FunctionBody",
    "LedgerFunction",
    "ProvidedObject",
    "UnrecordedFallout",
    "build_ledger",
    "canonical_ledger_payload",
    "census_unrecorded_fallout",
    "function_bodies",
    "ledger_translation_units",
    "read_ledger",
    "select_providers",
    "write_ledger",
]
