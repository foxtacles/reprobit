"""Cohesive build, evidence, verification, verdict, and report engine."""

from __future__ import annotations

import json
import marshal
import os
import re
import stat
import sys
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from types import CodeType, MappingProxyType
from typing import Literal, Protocol

from reprobit import __version__
from reprobit.build import BuildPlan, BuildStep
from reprobit.evidence_audit import EvidenceAudit, EvidenceAuditor, EvidenceClaim, EvidenceIssue
from reprobit.execution import (
    BuildExecutionReceipt,
    BuildExecutor,
    EngineError,
    FileReceipt,
    RuntimeEvidence,
    RuntimeEvidenceContext,
    RuntimeEvidenceProvider,
    StepExecutionReceipt,
    TargetOracle,
    TargetVerification,
)
from reprobit.implementation import (
    package_implementation_digest,
    revalidate_package_implementation,
)
from reprobit.model import AuthenticityPolicy, Digest, Verdict
from reprobit.process import CommandSpec, ProcessSupervisor
from reprobit.report import (
    AuditIssueSummary,
    BuildExecutionSummary,
    ComponentIdentity,
    ExecutionFileReceipt,
    ExecutionStepReceipt,
    ProducerSummary,
    ProofReport,
    Report,
    RuntimeBindingPreimage,
    RuntimeProofBinding,
    StageTiming,
    TargetComparisonSummary,
)
from reprobit.report_io import render_report_html
from reprobit.scheduler import TaskScheduler, TaskSpec
from reprobit.schema import ProjectBundle
from reprobit.secure_paths import (
    SecureFileSnapshot,
    SecurePathError,
    atomic_publish_relative,
    remove_published_relative,
    reseal_relative_file,
)
from reprobit.strict_json import canonical_json
from reprobit.verify import LiteralVerifier, SealedFileOracle

_BUILTIN_COMPOSITION_ID = "classic-msvc-producer-graph-v1"


def _secure_report_location(path: Path) -> tuple[Path, str]:
    """Anchor an absolute report path at its filesystem root without resolving it."""

    absolute = Path(os.path.abspath(path))
    if not absolute.anchor or len(absolute.parts) < 2:
        raise EngineError(f"report destination has no secure relative path: {path}")
    return Path(absolute.anchor), PurePosixPath(*absolute.parts[1:]).as_posix()


def _publish_report_payloads(
    payloads: Mapping[Path, bytes],
    *,
    final_reseal: Callable[[], None],
) -> None:
    """Prestage reports, reseal targets, commit durably, then reseal again.

    If a target changes during report publication, every newly committed report
    whose staged inode is still present is removed before the error escapes.
    Thus a failed run cannot leave a stale report that appears complete.
    """

    if len({path.resolve(strict=False) for path in payloads}) != len(payloads):
        raise EngineError("report destinations must be distinct")
    destinations = [
        (*_secure_report_location(path), path, payload)
        for path, payload in sorted(payloads.items(), key=lambda item: str(item[0]))
    ]
    published: list[tuple[Path, str, SecureFileSnapshot]] = []
    try:
        final_reseal()
        for root, relative, destination, payload in destinations:
            try:
                snapshot = atomic_publish_relative(root, relative, payload)
            except SecurePathError as exc:
                raise EngineError(f"cannot securely publish report {destination}: {exc}") from exc
            published.append((root, relative, snapshot))
        final_reseal()
        for root, relative, snapshot in published:
            try:
                reseal_relative_file(root, relative, expected=snapshot)
            except SecurePathError as exc:
                raise EngineError(
                    f"published report changed before completion: {snapshot.path}: {exc}"
                ) from exc
    except BaseException as original:
        rollback_errors: list[str] = []
        for root, relative, snapshot in reversed(published):
            try:
                if not remove_published_relative(root, relative, expected=snapshot):
                    rollback_errors.append(
                        f"{snapshot.path}: published snapshot was replaced or mutated"
                    )
            except SecurePathError as exc:
                rollback_errors.append(f"{snapshot.path}: {exc}")
        if rollback_errors:
            raise EngineError(
                "secure report rollback failed: " + "; ".join(rollback_errors)
            ) from original
        raise




@dataclass(frozen=True, slots=True)
class ReportDestinations:
    json: Path | None = None
    html: Path | None = None

    def __post_init__(self) -> None:
        if (
            self.json is not None
            and self.html is not None
            and self.json.resolve(strict=False) == self.html.resolve(strict=False)
        ):
            raise EngineError("JSON and HTML reports cannot share one path")


@dataclass(frozen=True, slots=True)
class EngineRequest:
    """Low-level injectable engine inputs.

    :meth:`ReproductionEngine.run` accepts this shape only when it resolves to
    ReproBit's closed built-in adapter/provider composition. Synthetic
    executors and providers belong exclusively behind
    :meth:`ReproductionEngine.run_unsafe_for_testing`, whose result can never
    carry a clean verdict.
    """

    bundle: ProjectBundle
    build_plan: BuildPlan
    project_root: Path
    run_root: Path
    oracles: tuple[TargetOracle, ...]
    evidence_providers: tuple[RuntimeEvidenceProvider, ...] = ()
    jobs: int = 1
    cold: bool = True
    reports: ReportDestinations = ReportDestinations()
    build_executor: BuildExecutor | None = None

    def __post_init__(self) -> None:
        if not self.project_root.is_absolute() or not self.run_root.is_absolute():
            raise EngineError("project_root and run_root must be absolute")
        if self.jobs < 1:
            raise EngineError("engine jobs must be at least one")
        oracle_ids = [oracle.target_id for oracle in self.oracles]
        if len(set(oracle_ids)) != len(oracle_ids):
            raise EngineError("target oracle ids must be unique")
        if any(not isinstance(oracle.capability, SealedFileOracle) for oracle in self.oracles):
            raise EngineError("literal verification requires sealed file-oracle capabilities")
        provider_names = [provider.name for provider in self.evidence_providers]
        if any(not name for name in provider_names) or len(set(provider_names)) != len(
            provider_names
        ):
            raise EngineError("runtime evidence provider names must be non-empty and unique")


@dataclass(frozen=True, slots=True)
class EngineResult:
    build: BuildExecutionReceipt
    targets: tuple[TargetVerification, ...]
    evidence: EvidenceAudit
    verdict: Verdict
    report: Report

    def accepts(self, policy: AuthenticityPolicy) -> bool:
        """Evaluate policy without letting quarantine hide other origin defects."""

        if policy is AuthenticityPolicy.CLEAN:
            return self.verdict.clean
        return (
            self.verdict.cold
            and self.verdict.byte_exact
            and self.verdict.logic_certified
            and self.evidence.origin_integrity
        )


class ExecutionPathResolver(Protocol):
    """Translate a build-plan path into a native execution path."""

    def resolve(self, value: str, *, cwd: Path | None = None) -> Path: ...


@dataclass(frozen=True, slots=True)
class HostPathResolver:
    """Resolver for plans already expressed as native host paths."""

    def resolve(self, value: str, *, cwd: Path | None = None) -> Path:
        if os.name != "nt" and re.match(r"^[A-Za-z]:[\\/]", value):
            raise EngineError(f"logical Windows path {value!r} needs an execution-backend resolver")
        path = Path(value)
        if not path.is_absolute():
            if cwd is None:
                raise EngineError(f"command cwd must be absolute: {value!r}")
            path = cwd / path
        return path.resolve(strict=False)


class BuildPlanExecutor:
    """Execute a canonical plan through the bounded DAG scheduler."""

    def __init__(
        self,
        *,
        run_root: Path,
        max_workers: int,
        path_resolver: ExecutionPathResolver | None = None,
        supervisor: ProcessSupervisor | None = None,
        resource_limits: Mapping[str, int] | None = None,
    ) -> None:
        if not run_root.is_absolute():
            raise EngineError("executor run_root must be absolute")
        if max_workers < 1:
            raise EngineError("executor max_workers must be at least one")
        self.run_root = run_root
        self.max_workers = max_workers
        self.path_resolver = path_resolver or HostPathResolver()
        self.supervisor = supervisor
        self.resource_limits = MappingProxyType(dict(resource_limits or {}))

    def execute(
        self,
        plan: BuildPlan,
        *,
        cold: bool,
        required_outputs: Iterable[Path] = (),
    ) -> BuildExecutionReceipt:
        working_directories = {step.id: self.path_resolver.resolve(step.cwd) for step in plan.steps}
        inputs = {
            (step.id, value): self.path_resolver.resolve(value, cwd=working_directories[step.id])
            for step in plan.steps
            for value in step.inputs
        }
        outputs = {
            (step.id, value): self.path_resolver.resolve(value, cwd=working_directories[step.id])
            for step in plan.steps
            for value in step.outputs
        }
        output_owner: dict[Path, str] = {}
        for (step_id, declared), path in outputs.items():
            previous = output_owner.get(path)
            if previous is not None:
                raise EngineError(
                    f"steps {previous!r} and {step_id!r} resolve outputs to the same path: "
                    f"{declared!r} -> {path}"
                )
            output_owner[path] = step_id
        self._validate_produced_input_dependencies(plan, inputs, output_owner)

        target_outputs = tuple(path.resolve(strict=False) for path in required_outputs)
        all_output_paths = set(output_owner).union(target_outputs)
        run_root_dirty = self.run_root.exists() and any(self.run_root.iterdir())
        preexisting = {path for path in all_output_paths if os.path.lexists(path)}
        if cold and run_root_dirty:
            raise EngineError(f"cold run root is not empty: {self.run_root}")
        if cold and preexisting:
            rendered = ", ".join(str(path) for path in sorted(preexisting))
            raise EngineError(f"cold run outputs already exist: {rendered}")

        external_inputs = sorted(
            {path for path in inputs.values() if path not in output_owner},
            key=str,
        )
        input_receipts = tuple(
            self._file_receipt(path, fresh=False, producer_step=None) for path in external_inputs
        )

        def task_for(step: BuildStep) -> TaskSpec:
            cwd = working_directories[step.id]

            def command(workspace: object) -> CommandSpec:
                # The scheduler invokes factories only after their dependencies,
                # so generated working directories and inputs can be checked here.
                from reprobit.scheduler import TaskWorkspace

                if not isinstance(workspace, TaskWorkspace):
                    raise TypeError("scheduler supplied an invalid task workspace")
                if not cwd.is_dir():
                    raise EngineError(f"build-step cwd does not exist: {cwd}")
                for declared in step.inputs:
                    self._require_regular(inputs[(step.id, declared)], "build input")
                return CommandSpec.create(
                    step.argv,
                    cwd=cwd,
                    environment=step.environment,
                    timeout_seconds=step.timeout_seconds,
                    log_path=workspace.logs / "process.log",
                )

            return TaskSpec(
                task_id=step.id,
                command=command,
                dependencies=step.depends_on,
            )

        scheduler = TaskScheduler(
            run_root=self.run_root,
            max_workers=self.max_workers,
            supervisor=self.supervisor,
            resource_limits=self.resource_limits,
        )
        try:
            results = scheduler.run(task_for(step) for step in plan.steps)
        finally:
            scheduler.close()

        for before in input_receipts:
            after = self._file_receipt(
                before.path,
                fresh=False,
                producer_step=None,
            )
            if (
                before.digest != after.digest
                or before.size != after.size
                or before.device != after.device
                or before.inode != after.inode
            ):
                raise EngineError(f"declared build input changed during execution: {before.path}")

        output_receipts: list[FileReceipt] = []
        for path in sorted(all_output_paths, key=str):
            output_receipts.append(
                self._file_receipt(
                    path,
                    fresh=path not in preexisting,
                    producer_step=output_owner.get(path),
                )
            )
        input_identities = {(item.device, item.inode) for item in input_receipts}
        aliased_inputs = [
            item.path for item in output_receipts if (item.device, item.inode) in input_identities
        ]
        if aliased_inputs:
            rendered = ", ".join(str(path) for path in aliased_inputs)
            raise EngineError(f"declared outputs alias build inputs: {rendered}")
        step_receipts = tuple(
            StepExecutionReceipt(
                step_id=step.id,
                returncode=results[step.id].process.returncode,
                attempts=results[step.id].process.attempts,
                duration_seconds=results[step.id].process.duration_seconds,
                output_digest=Digest.from_bytes(results[step.id].process.output),
                command_digest=_command_digest(step, working_directories[step.id]),
            )
            for step in plan.steps
        )
        return BuildExecutionReceipt(
            cold=cold and not run_root_dirty and not preexisting,
            inputs=input_receipts,
            outputs=tuple(output_receipts),
            steps=step_receipts,
        )

    def _file_receipt(self, path: Path, *, fresh: bool, producer_step: str | None) -> FileReceipt:
        self._require_regular(path, "declared artifact")
        digest = sha256()
        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
            with os.fdopen(descriptor, "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise EngineError(f"declared artifact is not regular: {path}")
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
                after = os.fstat(stream.fileno())
        except OSError as error:
            raise EngineError(f"cannot receipt declared artifact {path}: {error}") from error
        before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if before_identity != after_identity:
            raise EngineError(f"declared artifact changed while it was receipted: {path}")
        return FileReceipt(
            path=path,
            digest=Digest(value=digest.hexdigest()),
            size=after.st_size,
            fresh=fresh,
            producer_step=producer_step,
            device=after.st_dev,
            inode=after.st_ino,
        )

    @staticmethod
    def _require_regular(path: Path, label: str) -> None:
        if path.is_symlink() or not path.is_file():
            raise EngineError(f"{label} is missing, non-regular, or a symlink: {path}")

    @staticmethod
    def _validate_produced_input_dependencies(
        plan: BuildPlan,
        inputs: Mapping[tuple[str, str], Path],
        output_owner: Mapping[Path, str],
    ) -> None:
        by_id = {step.id: step for step in plan.steps}

        def ancestors(step_id: str) -> set[str]:
            result: set[str] = set()
            pending = list(by_id[step_id].depends_on)
            while pending:
                dependency = pending.pop()
                if dependency in result:
                    continue
                result.add(dependency)
                pending.extend(by_id[dependency].depends_on)
            return result

        for (consumer, _), path in inputs.items():
            producer = output_owner.get(path)
            if producer is not None and producer not in ancestors(consumer):
                raise EngineError(
                    f"step {consumer!r} consumes {path} from {producer!r} without a dependency"
                )



@dataclass(frozen=True, slots=True)
class _ExecutionIdentity:
    adapter: ComponentIdentity
    providers: tuple[ComponentIdentity, ...]
    package: ComponentIdentity
    unsafe: bool = False


def _revalidate_package_identity(identity: _ExecutionIdentity) -> None:
    """Bind a high-assurance run to the package bytes recorded at entry."""

    if identity.unsafe:
        return
    try:
        revalidate_package_implementation(identity.package.digest)
    except RuntimeError as exc:
        raise EngineError(str(exc)) from exc


def _module_digest(component: type[object]) -> Digest:
    module = sys.modules.get(component.__module__)
    source = getattr(module, "__file__", None)
    if not isinstance(source, str):
        raise EngineError(
            f"cannot content-identify component {component.__module__}.{component.__qualname__}"
        )
    path = Path(source)
    if path.suffix in {".pyc", ".pyo"}:
        candidate = path.with_suffix(".py")
        if candidate.is_file():
            path = candidate
    if path.is_symlink() or not path.is_file():
        raise EngineError(f"component implementation is not a regular file: {path}")
    methods: list[dict[str, str]] = []
    for name, member in sorted(vars(component).items()):
        callables: tuple[object, ...]
        if isinstance(member, (classmethod, staticmethod)):
            callables = (member.__func__,)
        elif isinstance(member, property):
            callables = tuple(
                item for item in (member.fget, member.fset, member.fdel) if item is not None
            )
        else:
            callables = (member,)
        for index, callable_value in enumerate(callables):
            code = getattr(callable_value, "__code__", None)
            if isinstance(code, CodeType):
                methods.append(
                    {
                        "name": f"{name}.{index}",
                        "digest": Digest.from_bytes(marshal.dumps(_normalized_code(code))).value,
                    }
                )
    return Digest.from_bytes(
        canonical_json(
            {
                "module_source": Digest.from_path(path),
                "loaded_class_code": methods,
            }
        )
    )


def _normalized_code(code: CodeType) -> CodeType:
    constants = tuple(
        _normalized_code(item) if isinstance(item, CodeType) else item for item in code.co_consts
    )
    return code.replace(co_consts=constants, co_filename="", co_firstlineno=1)


def _package_component_identity() -> ComponentIdentity:
    try:
        implementation_digest = package_implementation_digest()
    except RuntimeError as exc:
        raise EngineError(str(exc)) from exc
    return ComponentIdentity(
        role="package",
        id="reprobit",
        implementation="reprobit",
        package="reprobit",
        version=__version__,
        digest=implementation_digest,
    )


def _component_identity(
    component: type[object],
    *,
    role: Literal["adapter", "evidence-provider"],
    identity: str,
    builtin: bool,
) -> ComponentIdentity:
    implementation = f"{component.__module__}.{component.__qualname__}"
    if builtin:
        implementation_digest = _module_digest(component)
    else:
        try:
            implementation_digest = _module_digest(component)
        except EngineError:
            # Synthetic in-memory test doubles have no content-addressable
            # module. Their descriptive fallback is safe only because this
            # entire execution path carries the permanent unsafe audit issue.
            implementation_digest = Digest.from_bytes(implementation.encode("utf-8"))
    return ComponentIdentity(
        role=role,
        id=identity,
        implementation=implementation,
        package="reprobit" if builtin else "unsafe",
        version=__version__ if builtin else "unversioned",
        digest=implementation_digest,
    )


def _resolve_builtin_identity(request: EngineRequest) -> _ExecutionIdentity:
    # Imported at the call boundary to keep engine.py below classic_runtime.py in
    # the module dependency graph. Exact types prevent a same-name plugin or a
    # protocol-compatible object from entering the high-assurance path.
    try:
        from reprobit.classic_runtime import (
            ClassicProducerGraphBuildExecutor,
            ClassicProducerGraphRuntimeEvidenceProvider,
        )
    except (ImportError, AttributeError) as exc:
        raise EngineError("built-in authenticity composition is unavailable") from exc

    executor = request.build_executor
    providers = request.evidence_providers
    if type(executor) is not ClassicProducerGraphBuildExecutor:
        raise EngineError(
            "high-assurance execution requires the closed built-in "
            f"{_BUILTIN_COMPOSITION_ID!r} composition; use "
            "run_unsafe_for_testing() for injected executors"
        )
    if len(providers) != 1 or type(providers[0]) is not ClassicProducerGraphRuntimeEvidenceProvider:
        raise EngineError(
            "high-assurance execution requires the paired built-in evidence provider; "
            "use run_unsafe_for_testing() for injected providers"
        )
    provider = providers[0]
    if getattr(executor, "evidence_provider", None) is not provider:
        raise EngineError("built-in evidence provider is not paired with its executor")
    if "execute" in vars(executor) or "issue" in vars(provider) or "name" in vars(provider):
        raise EngineError("built-in composition methods may not be instance-shadowed")
    return _ExecutionIdentity(
        adapter=_component_identity(
            ClassicProducerGraphBuildExecutor,
            role="adapter",
            identity=_BUILTIN_COMPOSITION_ID,
            builtin=True,
        ),
        providers=(
            _component_identity(
                ClassicProducerGraphRuntimeEvidenceProvider,
                role="evidence-provider",
                identity=provider.name,
                builtin=True,
            ),
        ),
        package=_package_component_identity(),
    )


def _resolve_unsafe_identity(request: EngineRequest) -> _ExecutionIdentity:
    executor_type = (
        type(request.build_executor) if request.build_executor is not None else BuildPlanExecutor
    )
    return _ExecutionIdentity(
        adapter=_component_identity(
            executor_type,
            role="adapter",
            identity="unsafe-engine-request",
            builtin=False,
        ),
        providers=tuple(
            sorted(
                (
                    _component_identity(
                        type(provider),
                        role="evidence-provider",
                        identity=provider.name,
                        builtin=False,
                    )
                    for provider in request.evidence_providers
                ),
                key=lambda item: (item.id, canonical_json(item)),
            )
        ),
        package=_package_component_identity(),
        unsafe=True,
    )


class ReproductionEngine:
    """Run a build and derive independent authenticity claims."""

    def __init__(
        self,
        *,
        path_resolver: ExecutionPathResolver | None = None,
        supervisor: ProcessSupervisor | None = None,
    ) -> None:
        self.path_resolver = path_resolver
        self.supervisor = supervisor

    def run(self, request: EngineRequest) -> EngineResult:
        """Execute only the closed built-in high-assurance composition."""

        if type(self) is not ReproductionEngine:
            raise EngineError("high-assurance execution refuses engine subclasses")
        return ReproductionEngine._run(self, request, _resolve_builtin_identity(request))

    def run_unsafe_for_testing(self, request: EngineRequest) -> EngineResult:
        """Execute injected components with a permanent non-clean audit marker.

        This entrypoint exists for unit tests and integration experiments. Its
        result is deliberately incapable of claiming toolchain origin or a
        clean verdict, even when the injected evidence otherwise passes.
        """

        if type(self) is not ReproductionEngine:
            raise EngineError("unsafe test execution refuses engine subclasses")
        return ReproductionEngine._run(self, request, _resolve_unsafe_identity(request))

    def _run(self, request: EngineRequest, identity: _ExecutionIdentity) -> EngineResult:
        _revalidate_package_identity(identity)
        if request.project_root.resolve(strict=False) != Path(request.bundle.root).resolve(
            strict=False
        ):
            raise EngineError("engine project_root differs from the loaded project tree")
        targets = tuple(sorted(request.bundle.spec.targets, key=lambda item: item.id))
        oracle_by_id = {oracle.target_id: oracle.capability for oracle in request.oracles}
        expected_ids = {target.id for target in targets}
        if set(oracle_by_id) != expected_ids:
            missing = sorted(expected_ids.difference(oracle_by_id))
            extra = sorted(set(oracle_by_id).difference(expected_ids))
            raise EngineError(f"target oracle mismatch; missing={missing!r}, extra={extra!r}")

        artifact_paths = tuple(
            (request.project_root / target.artifact).resolve(strict=False) for target in targets
        )
        if len(set(artifact_paths)) != len(artifact_paths):
            raise EngineError("target artifacts must resolve to distinct paths")
        report_paths = tuple(
            path.resolve(strict=False)
            for path in (request.reports.json, request.reports.html)
            if path is not None
        )
        collisions = set(report_paths).intersection(artifact_paths)
        if collisions:
            raise EngineError(
                "report destinations overlap target artifacts: "
                + ", ".join(str(path) for path in sorted(collisions))
            )
        build_started = time.monotonic()
        executor: BuildExecutor = request.build_executor or BuildPlanExecutor(
            run_root=request.run_root,
            max_workers=request.jobs,
            path_resolver=self.path_resolver,
            supervisor=self.supervisor,
        )
        build = executor.execute(
            request.build_plan,
            cold=request.cold,
            required_outputs=artifact_paths,
        )
        build_seconds = time.monotonic() - build_started

        verify_started = time.monotonic()
        oracle_documents = {
            document.target_id: document for document in request.bundle.oracle_documents
        }
        verifier = LiteralVerifier()
        verifications: list[TargetVerification] = []
        build_outputs = {item.path.resolve(strict=False): item for item in build.outputs}
        for target, artifact_path in zip(targets, artifact_paths, strict=True):
            comparison = verifier.verify(artifact_path, oracle_by_id[target.id])
            build_output = build_outputs[artifact_path]
            if (
                comparison.candidate_size != build_output.size
                or comparison.candidate_digest != build_output.digest.value
                or comparison.candidate_device != build_output.device
                or comparison.candidate_inode != build_output.inode
            ):
                raise EngineError(f"target {target.id!r} changed after its fresh build receipt")
            declared = oracle_documents[target.id]
            if (
                comparison.oracle_size != declared.image_size
                or comparison.oracle_digest != declared.image_digest.value
            ):
                raise EngineError(
                    f"sealed oracle for target {target.id!r} differs from its committed receipt"
                )
            verifications.append(TargetVerification(target.id, artifact_path, comparison))
        target_receipts = tuple(verifications)
        verify_seconds = time.monotonic() - verify_started

        evidence_started = time.monotonic()
        runtime_proof = _runtime_proof_binding(
            build,
            target_receipts,
            {item.id: item.artifact for item in request.bundle.spec.targets},
        )
        run_binding = runtime_proof.digest
        context = RuntimeEvidenceContext(
            bundle=request.bundle,
            build=build,
            targets=target_receipts,
            run_binding=run_binding,
        )
        runtime_evidence: list[RuntimeEvidence] = []
        for provider in request.evidence_providers:
            issued = provider.issue(context)
            if not isinstance(issued, RuntimeEvidence):
                raise EngineError(
                    f"runtime evidence provider {provider.name!r} returned an invalid value"
                )
            if issued.provider_id != provider.name:
                raise EngineError(
                    f"runtime evidence provider {provider.name!r} returned another provider id"
                )
            if issued.run_binding != run_binding:
                raise EngineError(
                    f"runtime evidence provider {provider.name!r} returned stale evidence"
                )
            runtime_evidence.append(issued)
        evidence = EvidenceAuditor().audit(
            request.bundle,
            build,
            target_receipts,
            tuple(runtime_evidence),
            request.project_root,
        )
        if identity.unsafe:
            unsafe_issue = EvidenceIssue(
                EvidenceClaim.ORIGIN,
                "unsafe-engine-request",
                "injected engine components are outside the built-in authenticity boundary",
            )
            evidence = EvidenceAudit(
                tuple(sorted({*evidence.issues, unsafe_issue})),
                evidence.quarantines,
            )
        elif _resolve_builtin_identity(request) != identity:
            raise EngineError("built-in component identity changed during execution")
        evidence_seconds = time.monotonic() - evidence_started
        verdict = Verdict(
            cold=build.cold,
            byte_exact=all(target.comparison.byte_exact for target in target_receipts),
            logic_certified=evidence.logic_certified,
            toolchain_origin=evidence.toolchain_origin,
            quarantines=evidence.quarantines,
        )
        proof = ProofReport.create(
            runtime=runtime_proof,
            artifacts=tuple(item for issued in runtime_evidence for item in issued.artifacts),
            provenance=tuple(item for issued in runtime_evidence for item in issued.provenance),
            certificates=tuple(item for issued in runtime_evidence for item in issued.certificates),
            producers=tuple(
                ProducerSummary(
                    id=item.id,
                    artifact_id=item.artifact_id,
                    step_id=item.step_id,
                    producer_kind=item.producer_kind.value,
                    tool_id=item.tool_id,
                    tool_digest=item.tool_digest,
                    artifact_digest=item.artifact_digest,
                    artifact_size=item.artifact_size,
                    ranges=item.ranges,
                    captured_before_overwrite=item.captured_before_overwrite,
                )
                for issued in runtime_evidence
                for item in issued.producers
            ),
            audit_issues=tuple(
                AuditIssueSummary(
                    claim=item.claim.value,
                    code=item.code,
                    message=item.message,
                )
                for item in evidence.issues
            ),
            adapter=identity.adapter,
            providers=identity.providers,
            package=identity.package,
        )
        report = Report.from_bundle(
            request.bundle,
            verdict,
            evidence=proof.summary,
            proof=proof,
            target_results={
                target.target_id: target.comparison.byte_exact for target in target_receipts
            },
            target_artifacts={
                target.target_id: (
                    target.comparison.candidate_size,
                    Digest(value=target.comparison.candidate_digest),
                )
                for target in target_receipts
            },
            timings=(
                StageTiming(stage="build", seconds=build_seconds),
                StageTiming(stage="evidence", seconds=evidence_seconds),
                StageTiming(stage="verify", seconds=verify_seconds),
            ),
            run_binding=run_binding,
        )
        final_reseal = getattr(executor, "reseal_published_targets", None)
        if final_reseal is not None and not callable(final_reseal):
            raise EngineError("build executor exposes an invalid final reseal hook")

        def reseal() -> None:
            _revalidate_package_identity(identity)
            if final_reseal is None:
                return
            try:
                final_reseal()
            except Exception as exc:
                raise EngineError(f"published targets changed before report commit: {exc}") from exc

        report_payloads: dict[Path, bytes] = {}
        if request.reports.json is not None:
            report_payloads[request.reports.json] = canonical_json(report)
        if request.reports.html is not None:
            report_payloads[request.reports.html] = render_report_html(report).encode("utf-8")
        if report_payloads:
            _publish_report_payloads(report_payloads, final_reseal=reseal)
        else:
            reseal()
        return EngineResult(build, target_receipts, evidence, verdict, report)




def _command_digest(step: BuildStep, cwd: Path) -> Digest:
    payload = {
        "argv": step.argv,
        "cwd": str(cwd),
        "environment": step.environment,
        "timeout_seconds": step.timeout_seconds,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return Digest.from_bytes(encoded)


def _runtime_proof_binding(
    build: BuildExecutionReceipt,
    targets: tuple[TargetVerification, ...],
    logical_artifacts: Mapping[str, str],
) -> RuntimeProofBinding:
    def file_receipt(item: FileReceipt) -> ExecutionFileReceipt:
        return ExecutionFileReceipt(
            path=str(item.path),
            digest=item.digest,
            size=item.size,
            fresh=item.fresh,
            producer_step=item.producer_step,
            device=item.device,
            inode=item.inode,
        )

    preimage = RuntimeBindingPreimage(
        build=BuildExecutionSummary(
            cold=build.cold,
            inputs=tuple(
                sorted(
                    (file_receipt(item) for item in build.inputs),
                    key=lambda item: (item.path.casefold(), item.path),
                )
            ),
            outputs=tuple(
                sorted(
                    (file_receipt(item) for item in build.outputs),
                    key=lambda item: (item.path.casefold(), item.path),
                )
            ),
            steps=tuple(
                sorted(
                    (
                        ExecutionStepReceipt(
                            id=item.step_id,
                            returncode=item.returncode,
                            attempts=item.attempts,
                            duration_seconds=item.duration_seconds,
                            output_digest=item.output_digest,
                            command_digest=item.command_digest,
                        )
                        for item in build.steps
                    ),
                    key=lambda item: (item.id.casefold(), item.id),
                )
            ),
        ),
        targets=tuple(
            sorted(
                (
                    TargetComparisonSummary(
                        id=item.target_id,
                        logical_artifact=logical_artifacts[item.target_id],
                        artifact=str(item.artifact),
                        candidate_digest=Digest(value=item.comparison.candidate_digest),
                        candidate_size=item.comparison.candidate_size,
                        oracle_digest=Digest(value=item.comparison.oracle_digest),
                        oracle_size=item.comparison.oracle_size,
                        byte_exact=item.comparison.byte_exact,
                        first_difference_offset=(item.comparison.first_difference_offset),
                        candidate_device=item.comparison.candidate_device,
                        candidate_inode=item.comparison.candidate_inode,
                    )
                    for item in targets
                ),
                key=lambda item: item.id,
            )
        ),
    )
    return RuntimeProofBinding.create(preimage)


__all__ = [
    "BuildPlanExecutor",
    "EngineRequest",
    "EngineResult",
    "ExecutionPathResolver",
    "HostPathResolver",
    "ReportDestinations",
    "ReproductionEngine",
]
