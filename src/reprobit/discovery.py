"""Bounded, resumable discovery of compiler-state interventions.

Discovery is deliberately outside ReproBit's certification boundary.  It may
compile many closed candidate states and compare their products with sealed
references, but its output is only a proposal.  A normal project adapter must
still regenerate and prove any proposal before it can become committed
authority.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
from collections.abc import Mapping, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from pathlib import Path
from typing import cast

from reprobit.cache import IncrementalCache, cache_key
from reprobit.discovery_contracts import (
    CellObservation,
    CompileReceipt,
    DeclarationState,
    DiscoveryAdapter,
    DiscoveryArtifactPayload,
    DiscoveryArtifactReceipt,
    DiscoveryCampaignReport,
    DiscoveryError,
    DiscoveryInputReceipt,
    DiscoveryPlan,
    DiscoveryProduct,
    DiscoveryStateExport,
    declaration_state_id,
    enumerate_declaration_states,
)
from reprobit.model import Digest
from reprobit.process import CancellationToken
from reprobit.progress import ProgressEmitter, ProgressObserver
from reprobit.secure_path_contracts import (
    SecurePathError,
    canonical_relative_path,
    canonical_system_path,
)
from reprobit.secure_paths import (
    atomic_publish_new_relative,
    read_relative_file,
)
from reprobit.strict_json import JsonValue, canonical_json


def _redirected_directory(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def require_discovery_directory(
    path: Path,
    *,
    label: str,
    mode: int = 0o755,
) -> Path:
    """Create or verify an absolute directory through a no-follow component walk."""

    absolute = canonical_system_path(Path(os.path.abspath(path)))
    if not absolute.anchor or absolute == Path(absolute.anchor):
        raise DiscoveryError(f"{label} must be below a filesystem root: {absolute}")
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            metadata = os.stat(current, follow_symlinks=False)
        except FileNotFoundError:
            try:
                os.mkdir(current, mode)
            except FileExistsError:
                pass
            except OSError as exc:
                raise DiscoveryError(f"cannot create {label}: {current}: {exc}") from exc
            try:
                metadata = os.stat(current, follow_symlinks=False)
            except OSError as exc:
                raise DiscoveryError(f"cannot inspect new {label}: {current}: {exc}") from exc
        except OSError as exc:
            raise DiscoveryError(f"cannot inspect {label}: {current}: {exc}") from exc
        if _redirected_directory(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise DiscoveryError(f"{label} has a redirected/non-directory component: {current}")
    return absolute


_DISCOVERY_WORKSPACE_FILES = frozenset(
    {
        "candidate.obj",
        "candidate.pdb",
        "compiler.log",
        "declarations.h",
        "unit.cpp",
    }
)


def _clear_discovery_workspace(path: Path, *, remove_directory: bool) -> None:
    """Remove only the admitted flat compiler files; never recurse."""

    directory = require_discovery_directory(path, label="discovery cell workspace")
    try:
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda item: item.name)
    except OSError as exc:
        raise DiscoveryError(f"cannot inspect discovery cell workspace: {directory}") from exc
    for entry in entries:
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise DiscoveryError(f"cannot inspect discovery workspace entry: {entry.path}") from exc
        if entry.name not in _DISCOVERY_WORKSPACE_FILES or not stat.S_ISREG(metadata.st_mode):
            raise DiscoveryError(f"discovery workspace contains an unadmitted entry: {entry.path}")
        try:
            os.unlink(entry.path)
        except OSError as exc:
            raise DiscoveryError(f"cannot clear discovery workspace entry: {entry.path}") from exc
    if remove_directory:
        try:
            os.rmdir(directory)
        except OSError as exc:
            raise DiscoveryError(f"cannot remove empty discovery workspace: {directory}") from exc


_CACHE_DOMAIN = "discovery-cell"
_OBSERVATION_CACHE_DOMAIN = "discovery-observation"


def discovery_cache_implementation(implementation_digest: Digest) -> str:
    """Bind resume records to the exact installed discovery implementation."""

    return f"reprobit-discovery-v1-{implementation_digest.value}"


def _identifier(prefix: str, material: object) -> str:
    return f"{prefix}.{hashlib.sha256(canonical_json(material)).hexdigest()[:24]}"


def _json_mapping(value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    normalized = dict(value)
    canonical_json(normalized)
    return normalized


def _canonical_artifact_prefix(value: str) -> str:
    try:
        canonical_relative_path(value)
    except SecurePathError:
        raise DiscoveryError("artifact path prefix must be canonical POSIX relative text") from None
    return value


def _publish_selected_artifacts(
    *,
    root: Path,
    logical_prefix: str,
    payloads: Sequence[DiscoveryArtifactPayload],
) -> tuple[tuple[DiscoveryStateExport, ...], tuple[DiscoveryArtifactReceipt, ...]]:
    """Publish only proposal-referenced objects into a convergent local CAS."""

    root = require_discovery_directory(root, label="discovery artifact store")
    states: dict[str, DiscoveryStateExport] = {}
    artifacts: dict[str, DiscoveryArtifactReceipt] = {}
    for payload in sorted(payloads, key=lambda item: item.artifact_id):
        object_bytes = bytes(payload.object_bytes)
        if not object_bytes:
            raise DiscoveryError(f"discovery artifact is empty: {payload.artifact_id}")
        digest = Digest.from_bytes(object_bytes)
        filename = f"{digest.value}.obj"
        try:
            atomic_publish_new_relative(root, filename, object_bytes)
        except SecurePathError as publication_error:
            try:
                current, snapshot = read_relative_file(root, filename)
            except SecurePathError as read_error:
                raise DiscoveryError(
                    f"discovery artifact publication is unsafe: {filename}"
                ) from read_error
            if current != object_bytes or snapshot.digest != digest:
                raise DiscoveryError(
                    f"discovery artifact CAS conflicts with selected bytes: {filename}"
                ) from publication_error
        logical_path = f"{logical_prefix}/{filename}"
        receipt = DiscoveryArtifactReceipt(
            artifact_id=payload.artifact_id,
            role=payload.role,
            symbol=payload.symbol,
            logical_path=logical_path,
            object=digest,
            object_size=len(object_bytes),
            cell_id=payload.cell_id,
        )
        prior_receipt = artifacts.setdefault(payload.artifact_id, receipt)
        if prior_receipt != receipt:
            raise DiscoveryError(
                f"discovery artifact identifier has conflicting payloads: {payload.artifact_id}"
            )
        if payload.cell_id is None:
            if payload.state is not None or payload.generated_declarations is not None:
                raise DiscoveryError("seed artifact unexpectedly names declaration state")
            continue
        if payload.state is None or payload.generated_declarations is None:
            raise DiscoveryError("compiler artifact omits its declaration state export")
        declaration_bytes = bytes(payload.generated_declarations)
        try:
            declaration_text = declaration_bytes.decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise DiscoveryError("generated declarations are not exact ASCII") from exc
        state = DiscoveryStateExport(
            cell_id=payload.cell_id,
            state_id=declaration_state_id(payload.state),
            state=payload.state,
            generated_declarations=declaration_text,
            generated_declarations_digest=Digest.from_bytes(declaration_bytes),
        )
        prior_state = states.setdefault(payload.cell_id, state)
        if prior_state != state:
            raise DiscoveryError(f"discovery cell has conflicting state exports: {payload.cell_id}")
    return (
        tuple(sorted(states.values(), key=lambda item: item.cell_id)),
        tuple(sorted(artifacts.values(), key=lambda item: item.artifact_id)),
    )


class DiscoveryCampaignRunner:
    """Execute finite cells with immutable per-state resume and typed progress."""

    def __init__(
        self,
        *,
        state_root: Path,
        workspace_root: Path,
        adapter: DiscoveryAdapter,
        jobs: int,
        artifact_path_prefix: str = "artifacts",
        input_receipts: Sequence[DiscoveryInputReceipt] = (),
        progress: ProgressObserver | None = None,
    ) -> None:
        if jobs < 1:
            raise DiscoveryError("discovery worker count must be positive")
        self.state_root = canonical_system_path(Path(os.path.abspath(state_root)))
        self.workspace_root = canonical_system_path(Path(os.path.abspath(workspace_root)))
        self.artifact_root = self.state_root / "artifacts"
        self.artifact_path_prefix = _canonical_artifact_prefix(artifact_path_prefix)
        self.adapter = adapter
        self.input_receipts = tuple(input_receipts)
        input_keys = tuple(
            (item.role.value, item.symbol or "", item.logical_path) for item in self.input_receipts
        )
        if input_keys != tuple(sorted(set(input_keys))):
            raise DiscoveryError("discovery input receipts must be unique and canonical")
        self.jobs = jobs
        self.emitter = ProgressEmitter(progress)

    def run(self, plan: DiscoveryPlan) -> DiscoveryCampaignReport:
        with self.emitter.phase(
            "discovery-enumerate",
            "enumerating declaration states",
        ) as enumeration_phase:
            states = enumerate_declaration_states(plan)
            progress_total = len(states) + 3
            plan_digest = Digest.from_bytes(canonical_json(plan))
            compile_implementation = self.adapter.compile_implementation_digest()
            analysis_implementation = self.adapter.analysis_implementation_digest()
            compile_authority = self.adapter.compile_authority_digest()
            analysis_authority = Digest.from_bytes(
                canonical_json(
                    {
                        "adapter_authority": self.adapter.analysis_authority_digest(
                            compile_authority
                        ),
                        "implementation": analysis_implementation,
                    }
                )
            )
            campaign_id = _identifier(
                "campaign",
                {
                    "adapter": self.adapter.identity,
                    "compile_authority": compile_authority,
                    "analysis_authority": analysis_authority,
                    "compile_implementation": compile_implementation,
                    "analysis_implementation": analysis_implementation,
                    "plan": plan_digest,
                },
            )
            enumeration_phase.advance(
                completed=1,
                total=progress_total,
                phase="discovery-enumerate",
                node_id="declaration-states",
            )

        self.state_root = require_discovery_directory(
            self.state_root,
            label="discovery cache state",
        )
        self.workspace_root = require_discovery_directory(
            self.workspace_root,
            label="discovery workspace root",
        )
        workspace_cells = require_discovery_directory(
            self.workspace_root / "cells",
            label="discovery workspace cells",
        )
        cache = IncrementalCache(
            self.state_root,
            implementation=discovery_cache_implementation(compile_implementation),
        )
        completed = 0
        built = 0
        cached = 0
        observed_functions = 0
        products: list[DiscoveryProduct] = []
        failures: dict[str, BaseException] = {}
        cancellation = CancellationToken()

        try:
            # One GC-visible lease intentionally spans all workers.  CacheLease
            # record operations are path-local and immutable-publication based;
            # its only invocation-local field is closed after this pool drains.
            # A concurrency regression test exercises lookup/restore/store races.
            with (
                cache.lease() as lease,
                self.emitter.phase("discovery-compile", "compiling declaration states") as phase,
            ):

                def execute(state: DeclarationState) -> tuple[DiscoveryProduct, bool]:
                    cancellation.raise_if_cancelled()
                    state_id = declaration_state_id(state)
                    adapter_material = _json_mapping(self.adapter.cache_material(state))
                    workspace_id = _identifier(
                        "workspace",
                        {
                            "adapter": self.adapter.identity,
                            "compile_authority": compile_authority,
                            "state": state,
                            "adapter_material": adapter_material,
                        },
                    )
                    cell_root = workspace_cells / workspace_id
                    if os.path.lexists(cell_root):
                        _clear_discovery_workspace(
                            cell_root,
                            remove_directory=False,
                        )
                    else:
                        require_discovery_directory(
                            cell_root,
                            label="discovery cell workspace",
                        )
                    working_directory = os.fspath(cell_root)
                    material: dict[str, JsonValue] = {
                        "adapter": self.adapter.identity,
                        "compile_authority": cast(
                            JsonValue, compile_authority.model_dump(mode="json")
                        ),
                        "compile_implementation": cast(
                            JsonValue, compile_implementation.model_dump(mode="json")
                        ),
                        "state": cast(JsonValue, state.model_dump(mode="json")),
                        "adapter_material": adapter_material,
                        "working_directory": working_directory,
                    }
                    key = cache_key(
                        _CACHE_DOMAIN,
                        material,
                        implementation=cache.implementation,
                    )
                    cell_id = _identifier("cell", {"key": key})
                    object_path = cell_root / "candidate.obj"
                    record = lease.lookup(_CACHE_DOMAIN, key)
                    hit = record is not None
                    restored_object_digest: Digest | None = None
                    if record is not None:
                        metadata = dict(record.metadata)
                        if metadata.get("schema_version") != 3:
                            raise DiscoveryError(f"cached discovery cell is malformed: {cell_id}")
                        if metadata.get("state_id") != state_id:
                            raise DiscoveryError(f"cached discovery state differs: {cell_id}")
                        raw_receipt = metadata.get("compile_receipt")
                        if not isinstance(raw_receipt, dict):
                            raise DiscoveryError(
                                f"cached discovery compile receipt is malformed: {cell_id}"
                            )
                        receipt = CompileReceipt.model_validate(raw_receipt)
                        if receipt.working_directory != working_directory:
                            raise DiscoveryError(
                                f"compiler working directory differs from the cache key: {cell_id}"
                            )
                        restored = lease.restore_selected(
                            record,
                            {"candidate.obj": object_path},
                            allowed_root=cell_root,
                        )
                        restored_object_digest = restored["candidate.obj"].digest
                    else:
                        output = self.adapter.compile(
                            state,
                            cell_root,
                            cancellation,
                        )
                        try:
                            resolved = output.object_path.resolve(strict=True)
                            resolved.relative_to(cell_root.resolve(strict=True))
                        except (OSError, ValueError) as exc:
                            raise DiscoveryError(
                                f"adapter returned an object outside its cell workspace: {cell_id}"
                            ) from exc
                        if not resolved.is_file():
                            raise DiscoveryError(f"adapter returned no regular object: {cell_id}")
                        if resolved != object_path:
                            shutil.copyfile(resolved, object_path)
                        receipt = output.receipt
                        if receipt.working_directory != working_directory:
                            raise DiscoveryError(
                                f"compiler working directory differs from the cache key: {cell_id}"
                            )
                        record = lease.store(
                            _CACHE_DOMAIN,
                            key,
                            {"candidate.obj": object_path},
                            metadata={
                                "schema_version": 3,
                                "state_id": state_id,
                                "compile_receipt": cast(JsonValue, receipt.model_dump(mode="json")),
                                "adapter_metadata": _json_mapping(output.metadata),
                            },
                        )
                    object_digest = (
                        restored_object_digest
                        if restored_object_digest is not None
                        else Digest.from_path(object_path)
                    )
                    observation_material: dict[str, JsonValue] = {
                        "analysis_implementation": cast(
                            JsonValue,
                            analysis_implementation.model_dump(mode="json"),
                        ),
                        "cell_key": key,
                        "object": cast(JsonValue, object_digest.model_dump(mode="json")),
                    }
                    observation_key = cache_key(
                        _OBSERVATION_CACHE_DOMAIN,
                        observation_material,
                        implementation=cache.implementation,
                    )
                    observation_record = lease.lookup(
                        _OBSERVATION_CACHE_DOMAIN,
                        observation_key,
                    )
                    if observation_record is None:
                        observation = self.adapter.observe(
                            cell_id=cell_id,
                            state=state,
                            object_path=object_path,
                            receipt=receipt,
                        )
                    else:
                        observation_metadata = dict(observation_record.metadata)
                        raw_observation = observation_metadata.get("observation")
                        if (
                            observation_metadata.get("schema_version") != 1
                            or observation_metadata.get("object")
                            != object_digest.model_dump(mode="json")
                            or not isinstance(raw_observation, dict)
                        ):
                            raise DiscoveryError(
                                f"cached discovery observation is malformed: {cell_id}"
                            )
                        observation = CellObservation.model_validate_json(
                            canonical_json(raw_observation)
                        )
                    if (
                        observation.cell_id != cell_id
                        or observation.state_id != state_id
                        or observation.compile != receipt
                    ):
                        raise DiscoveryError(
                            f"discovery observation differs from its cell receipt: {cell_id}"
                        )
                    if observation.object != object_digest:
                        raise DiscoveryError(f"adapter object receipt differs: {cell_id}")
                    if observation_record is None:
                        lease.store(
                            _OBSERVATION_CACHE_DOMAIN,
                            observation_key,
                            {"candidate.obj": object_path},
                            metadata={
                                "schema_version": 1,
                                "object": cast(JsonValue, object_digest.model_dump(mode="json")),
                                "observation": cast(JsonValue, observation.model_dump(mode="json")),
                            },
                        )
                    return DiscoveryProduct(state, object_path, observation), hit

                worker_count = min(
                    self.jobs,
                    self.adapter.maximum_parallelism,
                    len(states),
                )
                if worker_count < 1:
                    raise DiscoveryError("discovery adapter exposes no compiler capacity")
                with ThreadPoolExecutor(
                    max_workers=worker_count,
                    thread_name_prefix="reprobit-discovery",
                ) as pool:
                    pending: dict[Future[tuple[DiscoveryProduct, bool]], DeclarationState] = {}
                    state_iterator = iter(states)
                    inflight_limit = worker_count * 2

                    def refill() -> None:
                        while len(pending) < inflight_limit:
                            try:
                                state = next(state_iterator)
                            except StopIteration:
                                return
                            pending[pool.submit(execute, state)] = state

                    try:
                        refill()
                        while pending:
                            done, _ = wait(pending, return_when=FIRST_COMPLETED)
                            for future in sorted(
                                done,
                                key=lambda item: declaration_state_id(pending[item]),
                            ):
                                state = pending.pop(future)
                                state_id = declaration_state_id(state)
                                if future.cancelled():
                                    continue
                                try:
                                    product, hit = future.result()
                                except Exception as exc:
                                    if not failures:
                                        failures[state_id] = exc
                                        cancellation.cancel(f"discovery cell {state_id} failed")
                                    continue
                                received_functions = len(product.observation.functions)
                                if (
                                    observed_functions + received_functions
                                    > plan.max_observed_functions
                                ):
                                    if not failures:
                                        failures[state_id] = DiscoveryError(
                                            "discovery campaign exceeds "
                                            f"max_observed_functions "
                                            f"{plan.max_observed_functions}"
                                        )
                                        cancellation.cancel(
                                            "discovery observed-function limit reached"
                                        )
                                    continue
                                products.append(product)
                                observed_functions += received_functions
                                completed += 1
                                if hit:
                                    cached += 1
                                else:
                                    built += 1
                                phase.cache(
                                    hit=hit,
                                    phase="discovery-compile",
                                    node_id=product.observation.cell_id,
                                    completed=1 + completed,
                                    total=progress_total,
                                )
                            if failures:
                                for future in pending:
                                    future.cancel()
                            else:
                                refill()
                    except BaseException:
                        cancellation.cancel("discovery interrupted")
                        for future in pending:
                            future.cancel()
                        raise

            if failures:
                first_id = sorted(failures)[0]
                first = failures[first_id]
                raise DiscoveryError(
                    f"discovery campaign failed in {len(failures)} cell(s); "
                    f"first={first_id}: {first}"
                ) from first

            products.sort(key=lambda item: item.observation.cell_id)
            with self.emitter.phase(
                "discovery-analyze",
                "analyzing compiler products",
            ) as analysis_phase:
                proposals = self.adapter.analyze(
                    campaign_id=campaign_id,
                    plan=plan,
                    products=products,
                )
                artifact_payloads = self.adapter.proposal_artifacts(
                    campaign_id=campaign_id,
                    proposals=proposals,
                    products=products,
                )
                analysis_phase.advance(
                    completed=len(states) + 2,
                    total=progress_total,
                    phase="discovery-analyze",
                    node_id="intervention-proposals",
                )
            with self.emitter.phase(
                "discovery-finalize",
                "validating and publishing discovery report",
            ) as final_phase:
                self.adapter.revalidate_compile_authority(compile_authority)
                current_compile_authority = compile_authority
                if (
                    Digest.from_bytes(
                        canonical_json(
                            {
                                "adapter_authority": self.adapter.analysis_authority_digest(
                                    current_compile_authority
                                ),
                                "implementation": self.adapter.analysis_implementation_digest(),
                            }
                        )
                    )
                    != analysis_authority
                ):
                    raise DiscoveryError("discovery analysis authority changed during analysis")
                if self.adapter.compile_implementation_digest() != compile_implementation:
                    raise DiscoveryError(
                        "discovery compiler implementation changed during analysis"
                    )
                selected_states, artifacts = _publish_selected_artifacts(
                    root=self.artifact_root,
                    logical_prefix=self.artifact_path_prefix,
                    payloads=artifact_payloads,
                )
                if self.adapter.analysis_implementation_digest() != analysis_implementation:
                    raise DiscoveryError(
                        "discovery analyzer implementation changed during analysis"
                    )
                proposals = tuple(sorted(proposals, key=lambda item: item.finding_id))
                report = DiscoveryCampaignReport(
                    campaign_id=campaign_id,
                    plan=plan,
                    plan_digest=plan_digest,
                    compile_implementation_digest=compile_implementation,
                    analysis_implementation_digest=analysis_implementation,
                    compile_authority_digest=compile_authority,
                    analysis_authority_digest=analysis_authority,
                    adapter=self.adapter.identity,
                    compiler=self.adapter.compiler_receipt(),
                    inputs=self.input_receipts,
                    cells_total=len(states),
                    cells_built=built,
                    cells_cached=cached,
                    observations=tuple(item.observation for item in products),
                    proposals=proposals,
                    selected_states=selected_states,
                    artifacts=artifacts,
                )
                for product in products:
                    _clear_discovery_workspace(
                        product.object_path.parent,
                        remove_directory=True,
                    )
                final_phase.advance(
                    completed=progress_total,
                    total=progress_total,
                    phase="discovery-finalize",
                    node_id=campaign_id,
                )
            return report
        except BaseException:
            # Failed workspaces intentionally remain inspectable.  Immutable
            # cells published before the failure can be resumed safely.
            raise


__all__ = [
    "DiscoveryCampaignRunner",
    "discovery_cache_implementation",
    "require_discovery_directory",
]
