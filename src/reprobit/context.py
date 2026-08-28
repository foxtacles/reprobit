"""Canonical compiler invocation contexts and receipts."""

from __future__ import annotations

import hashlib
import json
import ntpath
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Self

from reprobit.paths import PathContractError, logical_relative_to, normalize_logical_path


class CompileContextError(ValueError):
    """A compile context is incomplete, ambiguous, or internally inconsistent."""


def _safe_text(value: object, label: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or "\0" in value or (not empty and not value):
        raise CompileContextError(f"{label} must be a non-empty NUL-free string")
    return value


def _string_tuple(values: Iterable[str], label: str) -> tuple[str, ...]:
    return tuple(_safe_text(value, label) for value in values)


def _environment_tuple(
    environment: Mapping[str, str] | Iterable[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    entries = list(environment.items() if isinstance(environment, Mapping) else environment)
    seen: set[str] = set()
    normalized: list[tuple[str, str]] = []
    for key, value in entries:
        key = _safe_text(key, "environment key")
        value = _safe_text(value, f"environment value for {key}", empty=True)
        folded = key.casefold()
        if folded in seen:
            raise CompileContextError(f"duplicate case-insensitive environment key: {key}")
        if "=" in key:
            raise CompileContextError(f"environment key contains '=': {key}")
        seen.add(folded)
        normalized.append((key, value))
    return tuple(sorted(normalized, key=lambda item: (item[0].casefold(), item[0])))


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class CompileContext:
    """Every compiler-sensitive input for one translation-unit compile.

    ``argv`` is retained byte-for-code-point exactly and in order.  Dedicated
    path fields are canonical absolute DOS strings, enabling structural checks
    without rewriting the invocation that the compiler actually sees.
    """

    argv: tuple[str, ...]
    cwd: str
    source: str
    object_file: str
    pdb_file: str
    temp_directory: str
    include_paths: tuple[str, ...] = ()
    forced_includes: tuple[str, ...] = ()
    defines: tuple[str, ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    toolchain_profile: str = ""
    backend_profile: str = ""

    SCHEMA = "reprobit.compile-context.v1"

    def __post_init__(self) -> None:
        argv = _string_tuple(self.argv, "compiler argument")
        if not argv:
            raise CompileContextError("compiler argv must not be empty")
        object.__setattr__(self, "argv", argv)
        for field in ("cwd", "source", "object_file", "pdb_file", "temp_directory"):
            try:
                canonical = normalize_logical_path(getattr(self, field))
            except PathContractError as error:
                raise CompileContextError(f"invalid {field}: {error}") from error
            object.__setattr__(self, field, canonical)
        try:
            object.__setattr__(
                self,
                "include_paths",
                tuple(normalize_logical_path(path) for path in self.include_paths),
            )
            object.__setattr__(
                self,
                "forced_includes",
                tuple(normalize_logical_path(path) for path in self.forced_includes),
            )
        except PathContractError as error:
            raise CompileContextError(str(error)) from error
        object.__setattr__(self, "defines", _string_tuple(self.defines, "preprocessor definition"))
        object.__setattr__(self, "environment", _environment_tuple(self.environment))
        object.__setattr__(
            self, "toolchain_profile", _safe_text(self.toolchain_profile, "toolchain profile")
        )
        object.__setattr__(
            self, "backend_profile", _safe_text(self.backend_profile, "backend profile")
        )
        if ntpath.normcase(self.object_file) == ntpath.normcase(self.pdb_file):
            raise CompileContextError("object and PDB paths must differ")

    @classmethod
    def create(
        cls,
        *,
        argv: Iterable[str],
        cwd: str,
        source: str,
        object_file: str,
        pdb_file: str,
        temp_directory: str,
        include_paths: Iterable[str] = (),
        forced_includes: Iterable[str] = (),
        defines: Iterable[str] = (),
        environment: Mapping[str, str] | Iterable[tuple[str, str]] = (),
        toolchain_profile: str,
        backend_profile: str,
    ) -> Self:
        return cls(
            tuple(argv),
            cwd,
            source,
            object_file,
            pdb_file,
            temp_directory,
            tuple(include_paths),
            tuple(forced_includes),
            tuple(defines),
            _environment_tuple(environment),
            toolchain_profile,
            backend_profile,
        )

    @property
    def environment_mapping(self) -> dict[str, str]:
        return dict(self.environment)

    def canonical_data(self) -> dict[str, Any]:
        return {
            "schema": self.SCHEMA,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "source": self.source,
            "object_file": self.object_file,
            "pdb_file": self.pdb_file,
            "temp_directory": self.temp_directory,
            "include_paths": list(self.include_paths),
            "forced_includes": list(self.forced_includes),
            "defines": list(self.defines),
            "environment": [{"name": key, "value": value} for key, value in self.environment],
            "toolchain_profile": self.toolchain_profile,
            "backend_profile": self.backend_profile,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical_json(self.canonical_data())).hexdigest()

    def to_receipt(self) -> dict[str, Any]:
        receipt = self.canonical_data()
        receipt["sha256"] = self.digest
        return receipt

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(
            self.to_receipt(), sort_keys=True, indent=indent, ensure_ascii=False, allow_nan=False
        ) + ("\n" if indent is not None else "")

    @classmethod
    def from_receipt(cls, receipt: Mapping[str, Any]) -> Self:
        if receipt.get("schema") != cls.SCHEMA:
            raise CompileContextError("unsupported compile-context receipt schema")
        try:
            environment = tuple((entry["name"], entry["value"]) for entry in receipt["environment"])
            context = cls.create(
                argv=receipt["argv"],
                cwd=receipt["cwd"],
                source=receipt["source"],
                object_file=receipt["object_file"],
                pdb_file=receipt["pdb_file"],
                temp_directory=receipt["temp_directory"],
                include_paths=receipt["include_paths"],
                forced_includes=receipt["forced_includes"],
                defines=receipt["defines"],
                environment=environment,
                toolchain_profile=receipt["toolchain_profile"],
                backend_profile=receipt["backend_profile"],
            )
        except (KeyError, TypeError) as error:
            raise CompileContextError("malformed compile-context receipt") from error
        declared = receipt.get("sha256")
        if not isinstance(declared, str) or declared != context.digest:
            raise CompileContextError("compile-context receipt digest differs")
        allowed = set(context.canonical_data()) | {"sha256"}
        unknown = set(receipt) - allowed
        if unknown:
            raise CompileContextError(f"unknown compile-context fields: {sorted(unknown)}")
        return context

    def require_private_artifacts(self, logical_worker_root: str) -> None:
        """Require object, PDB, and temporary paths to stay in one worker seat."""

        for label, path in (
            ("object", self.object_file),
            ("PDB", self.pdb_file),
            ("temporary directory", self.temp_directory),
        ):
            try:
                logical_relative_to(path, logical_worker_root)
            except PathContractError as error:
                raise CompileContextError(
                    f"{label} path is not private to {logical_worker_root}: {path}"
                ) from error


__all__ = ["CompileContext", "CompileContextError"]
