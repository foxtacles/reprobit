"""Read live MSVC linker publics without reconstructing linker selection rules."""

from __future__ import annotations

import re
from collections.abc import Mapping


class LinkerMapError(ValueError):
    """A linker map cannot identify its live providers unambiguously."""


_ROW = re.compile(r"^\s*[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+[0-9A-Fa-f]{8,16}\s+(.*)$")


def provider_name(value: str) -> str:
    return value.strip().strip('"').replace("\\", "/").casefold()


def live_public_providers(
    payload: bytes,
    aliases: Mapping[str, frozenset[str]],
    *,
    external_archives: frozenset[str] = frozenset(),
    ambiguous_archives: frozenset[str] = frozenset(),
) -> dict[str, str]:
    """Resolve function rows against exact path or unique basename aliases.

    Archive aliases retain both archive and member names.  Unknown providers
    belong to libraries outside the project inventory and are not substituted
    with a project definition of the same symbol.
    """

    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise LinkerMapError(
            "linker map uses an unsupported legacy encoding; live-provider repair data "
            "requires ASCII logical object paths and public names"
        ) from exc
    in_publics = False
    finished = False
    selected: dict[str, str] = {}
    seen: set[str] = set()
    for line in lines:
        if "Publics by Value" in line and "Lib:Object" in line:
            if in_publics:
                raise LinkerMapError("linker map repeats its public table")
            in_publics = True
            continue
        if not in_publics:
            continue
        if line.strip().casefold().startswith("entry point at"):
            finished = True
            break
        if not line.strip():
            continue
        match = _ROW.fullmatch(line)
        if match is None:
            raise LinkerMapError("linker map has an unrecognized public row")
        symbol, tail = match.groups()
        fields = tail.split(None, 1)
        if not fields:
            raise LinkerMapError("linker map public has no provider fields")
        if fields[0] != "f":
            continue  # Data publics do not describe function bodies.
        if len(fields) != 2:
            raise LinkerMapError("linker map function has no provider")
        name = fields[1]
        name = re.sub(r"^i\s+", "", name)
        if symbol in seen:
            raise LinkerMapError(f"linker map repeats function {symbol!r}")
        seen.add(symbol)
        if any(provider_name(name).startswith(archive + ":") for archive in ambiguous_archives):
            raise LinkerMapError(f"linker map archive identity is ambiguous: {name!r}")
        candidates = aliases.get(provider_name(name), frozenset())
        if len(candidates) > 1:
            raise LinkerMapError(f"linker map provider is ambiguous: {name!r}")
        if candidates:
            selected[symbol] = next(iter(candidates))
        elif not any(
            provider_name(name).startswith(archive + ":") for archive in external_archives
        ):
            raise LinkerMapError(f"linker map provider is not an admitted input: {name!r}")
    if not in_publics or not finished:
        raise LinkerMapError("linker map has no complete public table")
    return selected
