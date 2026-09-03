"""Replay store for non-certifying donor compile probes.

A donor probe compile is a pure function of its compiler seat (the rendered
private arena inputs) and of the compile epoch: the producer graph (which pins
the toolchain lock and every compiler argument), the compiler lane
environment, the sealed include authority and the sealed effective source
tree the compiler may read.  Within one epoch a seat compiled once need never
be compiled again, whether by a later round of the same ``rbit repair`` or by
a later command.

The store is never consulted for certification: ``rbit verify`` and the
repair's final cold proof recompile everything.  Persisted entries carry the
digests of their payloads and are discarded on any mismatch, so a damaged file
can only cost a recompile.
"""

from __future__ import annotations

import json
import zlib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path

from reprobit.atomic_io import write_bytes_atomic
from reprobit.classic_execution_records import ClassicActiveCompilerEpoch
from reprobit.classic_runtime_probe import ClassicDonorProbeInput, ClassicDonorProbeOutput
from reprobit.execution import StepExecutionReceipt
from reprobit.model import Digest
from reprobit.producer_graph import ProducerGraphDocument, producer_graph_digest
from reprobit.strict_json import canonical_json

PROBE_STORE_FORMAT = "reprobit-donor-probe-outcome-v1"
PROBE_STORE_DIRECTORY = "repair-probes"
PROBE_STORE_VERSION = "v1"

ProbeSeatKey = tuple[str, str, str]
"""``(build target, logical source, donor request identity)``, the first two casefolded."""


@dataclass(frozen=True, slots=True)
class ClassicDonorCompileRefusal:
    """One expected candidate-specific compiler refusal, without a traceback."""

    donor_id: str
    reason: str


ClassicDonorCompileOutcome = ClassicDonorProbeOutput | ClassicDonorCompileRefusal


def compile_epoch_digest(
    graph: ProducerGraphDocument,
    compiler_environment_digest: Digest,
    compiler_epoch: ClassicActiveCompilerEpoch,
    *,
    effective_root: Path,
) -> str:
    """Name everything but the seat that a donor probe compile depends on."""

    authority = compiler_epoch.include_authority
    resolved_root = effective_root.resolve(strict=False)
    sealed_sources: list[list[object]] = []
    for path, (size, digest) in compiler_epoch.source_seal.items():
        try:
            relative = path.relative_to(resolved_root).as_posix()
        except ValueError:
            relative = path.as_posix()
        sealed_sources.append([relative, size, digest.value])
    sealed_sources.sort(key=lambda item: str(item[0]))
    material = {
        "compiler_environment": compiler_environment_digest.value,
        "format": PROBE_STORE_FORMAT,
        "generated_inputs": compiler_epoch.generated,
        "include_authority": {
            "files": [
                [item.logical_path, item.digest.value, item.size, item.origin.value]
                for item in authority.files
            ],
            "roots": list(authority.logical_roots),
        },
        "producer_graph": producer_graph_digest(graph).value,
        "source_seal": sealed_sources,
    }
    return sha256(canonical_json(material)).hexdigest()


def _entry_name(epoch: str, key: ProbeSeatKey) -> str:
    return sha256(canonical_json({"epoch": epoch, "key": list(key)})).hexdigest()


def _encode_output(epoch: str, key: ProbeSeatKey, output: ClassicDonorProbeOutput) -> bytes:
    payloads = [item.payload for item in output.rendered_inputs]
    payloads.extend((output.object_payload, output.pdb_payload))
    header = {
        "build_target": output.build_target,
        "epoch": epoch,
        "format": PROBE_STORE_FORMAT,
        "key": list(key),
        "object_digest": output.object_digest.value,
        "object_length": len(output.object_payload),
        "pdb_digest": output.pdb_digest.value,
        "pdb_length": len(output.pdb_payload),
        "producer_node_id": output.producer_node_id,
        "rendered_inputs": [
            {
                "digest": item.digest.value,
                "length": len(item.payload),
                "logical_path": item.logical_path,
                "size": item.size,
            }
            for item in output.rendered_inputs
        ],
        "source_reference": output.source_reference,
        "step": {
            "attempts": output.step.attempts,
            "command_digest": output.step.command_digest.value,
            "duration_seconds": output.step.duration_seconds,
            "output_digest": output.step.output_digest.value,
            "returncode": output.step.returncode,
            "step_id": output.step.step_id,
        },
        "translation_unit_id": output.translation_unit_id,
    }
    return canonical_json(header) + zlib.compress(b"".join(payloads), 6)


def _decode_output(
    data: bytes,
    *,
    epoch: str,
    key: ProbeSeatKey,
    donor_id: str,
) -> ClassicDonorProbeOutput | None:
    newline = data.find(b"\n")
    if newline < 0:
        return None
    try:
        header = json.loads(data[:newline].decode("utf-8"))
        body = zlib.decompress(data[newline + 1 :])
    except (UnicodeDecodeError, ValueError, zlib.error):
        return None
    if (
        not isinstance(header, dict)
        or header.get("format") != PROBE_STORE_FORMAT
        or header.get("epoch") != epoch
        or header.get("key") != list(key)
    ):
        return None
    try:
        offset = 0
        rendered: list[ClassicDonorProbeInput] = []
        for item in header["rendered_inputs"]:
            length = int(item["length"])
            payload = body[offset : offset + length]
            offset += length
            if len(payload) != length or Digest.from_bytes(payload).value != item["digest"]:
                return None
            rendered.append(
                ClassicDonorProbeInput(
                    str(item["logical_path"]),
                    Digest(value=str(item["digest"])),
                    int(item["size"]),
                    payload,
                )
            )
        object_length = int(header["object_length"])
        pdb_length = int(header["pdb_length"])
        object_payload = body[offset : offset + object_length]
        offset += object_length
        pdb_payload = body[offset : offset + pdb_length]
        offset += pdb_length
        if offset != len(body):
            return None
        object_digest = Digest(value=str(header["object_digest"]))
        pdb_digest = Digest(value=str(header["pdb_digest"]))
        if (
            Digest.from_bytes(object_payload) != object_digest
            or Digest.from_bytes(pdb_payload) != pdb_digest
        ):
            return None
        step = header["step"]
        receipt = StepExecutionReceipt(
            str(step["step_id"]),
            int(step["returncode"]),
            int(step["attempts"]),
            float(step["duration_seconds"]),
            Digest(value=str(step["output_digest"])),
            Digest(value=str(step["command_digest"])),
        )
        return ClassicDonorProbeOutput(
            donor_id,
            str(header["translation_unit_id"]),
            str(header["build_target"]),
            str(header["source_reference"]),
            str(header["producer_node_id"]),
            tuple(rendered),
            object_digest,
            pdb_digest,
            object_payload,
            pdb_payload,
            receipt,
        )
    except (KeyError, TypeError, ValueError):
        return None


class ClassicDonorCompileStore:
    """Replay donor compile outcomes by seat within a named compile epoch.

    Outcomes are kept in memory for the life of the store (one command).  When
    a directory is given, successful compiles are also written there and read
    back by later commands.  Refusals stay in memory only: a compiler error is
    deterministic for its seat, but a timeout or a killed process is not.
    """

    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory
        self._memory: dict[tuple[str, ProbeSeatKey], ClassicDonorCompileOutcome] = {}
        self.memory_hits = 0
        self.disk_hits = 0
        self.misses = 0
        self.stored = 0

    def __len__(self) -> int:
        return len(self._memory)

    def _path(self, epoch: str, key: ProbeSeatKey) -> Path | None:
        if self.directory is None:
            return None
        name = _entry_name(epoch, key)
        return self.directory / PROBE_STORE_VERSION / name[:2] / f"{name}.bin"

    def get(
        self, epoch: str, key: ProbeSeatKey, *, donor_id: str
    ) -> ClassicDonorCompileOutcome | None:
        """Return the outcome of ``key`` under ``epoch``, renamed to ``donor_id``."""

        cached = self._memory.get((epoch, key))
        if cached is not None:
            self.memory_hits += 1
            return replayed(cached, donor_id)
        path = self._path(epoch, key)
        if path is None or path.is_symlink() or not path.is_file():
            self.misses += 1
            return None
        try:
            data = path.read_bytes()
        except OSError:
            self.misses += 1
            return None
        decoded = _decode_output(data, epoch=epoch, key=key, donor_id=donor_id)
        if decoded is None:
            path.unlink(missing_ok=True)
            self.misses += 1
            return None
        self._memory[(epoch, key)] = decoded
        self.disk_hits += 1
        return decoded

    def put(self, epoch: str, key: ProbeSeatKey, outcome: ClassicDonorCompileOutcome) -> None:
        """Remember ``outcome`` for ``key`` under ``epoch``; persist successful compiles."""

        self._memory[(epoch, key)] = outcome
        path = self._path(epoch, key)
        if path is None or not isinstance(outcome, ClassicDonorProbeOutput):
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        write_bytes_atomic(path, _encode_output(epoch, key, outcome), fsync_directory=False)
        self.stored += 1

    def counters(self) -> Mapping[str, int]:
        return {
            "memory_hits": self.memory_hits,
            "disk_hits": self.disk_hits,
            "misses": self.misses,
            "stored": self.stored,
        }


def replayed(outcome: ClassicDonorCompileOutcome, donor_id: str) -> ClassicDonorCompileOutcome:
    """The same outcome under another candidate's probe id."""

    if isinstance(outcome, ClassicDonorCompileRefusal):
        return ClassicDonorCompileRefusal(donor_id, outcome.reason)
    return replace(outcome, donor_id=donor_id)


def probe_store_directory(state_root: Path) -> Path:
    """Where a project's state keeps its donor probe replay store."""

    return state_root / PROBE_STORE_DIRECTORY


def probe_store_usage(state_root: Path) -> tuple[int, int]:
    """``(files, bytes)`` currently held by the project's probe store."""

    directory = probe_store_directory(state_root)
    if directory.is_symlink() or not directory.is_dir():
        return 0, 0
    files = 0
    total = 0
    for path in directory.rglob("*"):
        if path.is_file() and not path.is_symlink():
            files += 1
            total += path.stat().st_size
    return files, total


__all__ = [
    "PROBE_STORE_DIRECTORY",
    "PROBE_STORE_FORMAT",
    "ClassicDonorCompileOutcome",
    "ClassicDonorCompileRefusal",
    "ClassicDonorCompileStore",
    "ProbeSeatKey",
    "compile_epoch_digest",
    "probe_store_directory",
    "probe_store_usage",
    "replayed",
]
