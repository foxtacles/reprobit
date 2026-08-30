"""Direct CLI ownership for bounded, non-certifying intervention discovery."""

from __future__ import annotations

import argparse
import os
import shutil
from collections import Counter
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from reprobit.cli_output import ACTIVITY_PHASE_KINDS, CLIOutput
from reprobit.cli_paths import CLIError, relative_output
from reprobit.model import Digest
from reprobit.msvc_compile import hold_wine_prefix
from reprobit.progress import ProgressEvent, ProgressKind, ProgressObserver
from reprobit.strict_json import canonical_json
from reprobit.transactions import CASTransaction

if TYPE_CHECKING:
    from reprobit.discovery_contracts import (
        DiscoveryCampaignReport,
        DiscoveryInputReceipt,
    )
    from reprobit.msvc_discovery import MsvcDiscoveryRequest
    from reprobit.msvc_discovery_coff import MsvcFunctionReference
    from reprobit.toolchains import ClassicMSVCToolchain


@dataclass(frozen=True, slots=True)
class _DiscoveryPaths:
    request: Path
    root: Path
    state: Path
    report_json: Path
    report_html: Path


@dataclass(frozen=True, slots=True)
class _RuntimeConfiguration:
    driver: Path
    runtime_paths: tuple[str, ...]
    support_files: tuple[Path, ...]
    wineserver: Path | None
    environment: Mapping[str, str]
    compiler_parallelism: int


@dataclass(frozen=True, slots=True)
class _CampaignInputs:
    request: MsvcDiscoveryRequest
    source: bytes
    references: tuple[MsvcFunctionReference, ...]
    seeds: Mapping[str, bytes]
    receipts: dict[str, str]
    report_inputs: tuple[DiscoveryInputReceipt, ...]
    folded_paths: dict[str, str]


def _run_discovery_wineserver_command(
    *,
    executable: Path,
    runtime_root: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    argument: str,
    phase: str,
) -> None:
    """Run one bounded command against the campaign's private Wine prefix."""

    from reprobit.process import CommandFailed, CommandSpec, ProcessError, ProcessSupervisor

    if argument not in {"-k", "-w"} or phase not in {"preflight", "cleanup"}:
        raise AssertionError("invalid discovery wineserver control command")
    action = "stop" if argument == "-k" else "wait"
    specification = CommandSpec.create(
        (os.fspath(executable), argument),
        cwd=runtime_root,
        environment=environment,
        timeout_seconds=timeout_seconds,
        log_path=runtime_root / f"wineserver-{phase}-{action}.log",
        output_limit=1024 * 1024,
    )
    try:
        with ProcessSupervisor() as supervisor:
            supervisor.run(specification)
    except ProcessError as exc:
        if (
            argument == "-k"
            and isinstance(exc, CommandFailed)
            and exc.result.returncode == 1
            and not exc.result.output.strip()
        ):
            # Wine reports exit 1 with no diagnostic when this private prefix
            # is already stopped. That is the requested state.
            return
        raise CLIError(f"discovery wineserver {phase} {action} failed: {exc}") from exc


@contextmanager
def _discovery_wineserver_lifecycle(
    *,
    executable: Path,
    runtime_root: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> Iterator[None]:
    """Clear, hold one pinned wineserver, then always stop and reap the prefix.

    The held foreground server is what compiler children attach to.  Without
    it, the first wine invocation on a cold prefix spawns the server and its
    services inside the compiler's own process group, and the drain invariant
    correctly refuses the compile."""

    primary_error: BaseException | None = None
    try:
        for argument in ("-k", "-w"):
            _run_discovery_wineserver_command(
                executable=executable,
                runtime_root=runtime_root,
                environment=environment,
                timeout_seconds=timeout_seconds,
                argument=argument,
                phase="preflight",
            )
        with hold_wine_prefix(
            environment,
            wineserver=executable,
            timeout_seconds=timeout_seconds,
        ):
            yield
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_errors: list[str] = []
        for argument in ("-k", "-w"):
            try:
                _run_discovery_wineserver_command(
                    executable=executable,
                    runtime_root=runtime_root,
                    environment=environment,
                    timeout_seconds=timeout_seconds,
                    argument=argument,
                    phase="cleanup",
                )
            except CLIError as exc:
                cleanup_errors.append(str(exc))
        if cleanup_errors:
            cleanup_error = CLIError("; ".join(cleanup_errors))
            if primary_error is not None:
                primary_error.add_note(f"discovery Wine cleanup also failed: {cleanup_error}")
            else:
                raise cleanup_error


def _replace_report_suffix(value: str, *, expected: str, replacement: str) -> str:
    path = Path(value)
    if path.suffix.casefold() != expected:
        raise CLIError(f"discovery {expected[1:].upper()} report path must end in {expected}")
    return os.fspath(path.with_suffix(replacement))


def _report_values(args: argparse.Namespace, request_path: Path) -> tuple[str, str]:
    json_value: str | None = args.report_json
    html_value: str | None = args.report_html
    if json_value is None and html_value is None:
        stem = f"{request_path.stem}.report"
        return f"{stem}.json", f"{stem}.html"
    if json_value is None:
        assert html_value is not None
        json_value = _replace_report_suffix(
            html_value,
            expected=".html",
            replacement=".json",
        )
    if html_value is None:
        html_value = _replace_report_suffix(
            json_value,
            expected=".json",
            replacement=".html",
        )
    _replace_report_suffix(json_value, expected=".json", replacement=".html")
    _replace_report_suffix(html_value, expected=".html", replacement=".json")
    return json_value, html_value


def _folded(value: Path) -> str:
    return value.as_posix().casefold().rstrip("/")


def _paths_overlap(left: Path, right: Path) -> bool:
    left_value = _folded(left)
    right_value = _folded(right)
    return (
        left_value == right_value
        or left_value.startswith(right_value + "/")
        or right_value.startswith(left_value + "/")
    )


def _resolve_paths(args: argparse.Namespace) -> _DiscoveryPaths:
    request_candidate = Path(args.request).expanduser()
    if not request_candidate.is_absolute():
        request_candidate = Path.cwd() / request_candidate
    if request_candidate.is_symlink() or not request_candidate.is_file():
        raise CLIError(f"discovery request is not an existing real file: {request_candidate}")
    request_path = request_candidate.resolve(strict=True)
    root = request_path.parent
    report_json_value, report_html_value = _report_values(args, request_path)
    report_json = relative_output(root, report_json_value)
    report_html = relative_output(root, report_html_value)
    state = relative_output(root, args.state_directory)
    if not state.parts:
        raise CLIError("discovery state directory must not be the request directory")
    if report_json.parent != report_html.parent:
        raise CLIError("discovery JSON and HTML reports must be sibling files")
    if _folded(report_json) == _folded(report_html):
        raise CLIError("discovery JSON and HTML report paths alias each other")
    if _paths_overlap(report_json, state) or _paths_overlap(report_html, state):
        raise CLIError("discovery report paths must not overlap discovery state")
    return _DiscoveryPaths(
        request=request_path,
        root=root,
        state=state,
        report_json=report_json,
        report_html=report_html,
    )


def _configure_posix_runtime(
    *,
    args: argparse.Namespace,
    installation: ClassicMSVCToolchain,
    toolchain_root: Path,
    runtime_root: Path,
) -> _RuntimeConfiguration:
    from reprobit.discovery import require_discovery_directory
    from reprobit.discovery_contracts import DiscoveryError

    driver = toolchain_root / "wine" / "x86" / "cl"
    runtime_candidates = (
        "wine/x86/cl",
        "wine/x86/msvcenv.sh",
        "wine/x86/wine-msvc.sh",
        "wine/x86/msvctricks.exe",
    )
    runtime_paths = tuple(
        relative
        for relative in runtime_candidates
        if installation.host_path(relative).is_file()
        and not installation.host_path(relative).is_symlink()
    )
    wine = shutil.which(args.wine)
    if wine is None:
        raise CLIError(f"Wine executable is not available: {args.wine}")
    wine_path = Path(wine).resolve(strict=True)
    wineserver = shutil.which(args.wineserver)
    if wineserver is None:
        raise CLIError(f"wineserver executable is not available: {args.wineserver}")
    wineserver_path = Path(wineserver).resolve(strict=True)
    host_home = runtime_root / "home"
    host_tmp = runtime_root / "tmp"
    xdg_runtime = runtime_root / "xdg-runtime"
    wine_prefix = runtime_root / "wine-prefix"
    try:
        for directory in (host_home, host_tmp, xdg_runtime, wine_prefix):
            require_discovery_directory(
                directory,
                label="discovery Wine runtime directory",
                mode=0o700,
            )
    except DiscoveryError as exc:
        raise CLIError(str(exc)) from exc
    environment = {
        "HOME": os.fspath(host_home),
        "USER": "reprobit",
        "LOGNAME": "reprobit",
        "TMPDIR": os.fspath(host_tmp),
        "XDG_RUNTIME_DIR": os.fspath(xdg_runtime),
        "WINEPREFIX": os.fspath(wine_prefix),
        "PATH": os.pathsep.join(
            dict.fromkeys(
                (
                    os.fspath(wine_path.parent),
                    os.fspath(wineserver_path.parent),
                    "/usr/bin",
                    "/bin",
                    "/usr/sbin",
                    "/sbin",
                )
            )
        ),
        "LC_ALL": "C",
        "LANG": "C",
        "WINEDEBUG": "-all",
        "MVK_CONFIG_LOG_LEVEL": "0",
    }
    return _RuntimeConfiguration(
        driver=driver,
        runtime_paths=runtime_paths,
        support_files=(wine_path, wineserver_path),
        wineserver=wineserver_path,
        environment=environment,
        compiler_parallelism=min(args.jobs, 4),
    )


def _configure_windows_runtime(
    *,
    args: argparse.Namespace,
    toolchain_root: Path,
    runtime_root: Path,
) -> _RuntimeConfiguration:
    from reprobit.discovery import require_discovery_directory
    from reprobit.discovery_contracts import DiscoveryError

    system_root = os.environ.get("SYSTEMROOT")
    if system_root is None:
        raise CLIError("native Windows has no SYSTEMROOT environment")
    host_tmp = runtime_root / "tmp"
    try:
        require_discovery_directory(
            host_tmp,
            label="discovery native temporary directory",
            mode=0o700,
        )
    except DiscoveryError as exc:
        raise CLIError(str(exc)) from exc
    environment = {
        "SYSTEMROOT": system_root,
        "TEMP": os.fspath(host_tmp),
        "TMP": os.fspath(host_tmp),
        "PATH": os.pathsep.join(
            (
                os.fspath(toolchain_root / "bin"),
                os.fspath(Path(system_root) / "System32"),
            )
        ),
        "INCLUDE": os.pathsep.join(
            (
                os.fspath(toolchain_root / "include"),
                os.fspath(toolchain_root / "mfc" / "include"),
            )
        ),
        "LIB": os.pathsep.join(
            (
                os.fspath(toolchain_root / "lib"),
                os.fspath(toolchain_root / "mfc" / "lib"),
            )
        ),
    }
    return _RuntimeConfiguration(
        driver=toolchain_root / "bin" / "CL.EXE",
        runtime_paths=(),
        support_files=(),
        wineserver=None,
        environment=environment,
        compiler_parallelism=args.jobs,
    )


def _configure_runtime(
    *,
    args: argparse.Namespace,
    installation: ClassicMSVCToolchain,
    toolchain_root: Path,
    runtime_root: Path,
) -> _RuntimeConfiguration:
    if os.name == "posix":
        return _configure_posix_runtime(
            args=args,
            installation=installation,
            toolchain_root=toolchain_root,
            runtime_root=runtime_root,
        )
    if os.name == "nt":
        return _configure_windows_runtime(
            args=args,
            toolchain_root=toolchain_root,
            runtime_root=runtime_root,
        )
    raise CLIError("discovery supports POSIX/Wine and native Windows")


@contextmanager
def _campaign_progress(output: CLIOutput) -> Iterator[ProgressObserver]:
    with output.producer_activity(
        "discovering reproducible compiler interventions"
    ) as update_progress:
        last_completed = 0
        campaign_total: int | None = None

        def observe(event: ProgressEvent) -> None:
            nonlocal campaign_total, last_completed
            if (
                event.kind
                in {
                    ProgressKind.UNIT_FINISHED,
                    ProgressKind.CACHE_HIT,
                    ProgressKind.CACHE_MISS,
                }
                and event.completed is not None
                and event.total is not None
                and event.node_id is not None
            ):
                last_completed = event.completed
                campaign_total = event.total
                update_progress(
                    event.completed,
                    event.total,
                    event.phase,
                    event.node_id,
                    event.kind,
                    event.reason,
                )
            elif event.kind in ACTIVITY_PHASE_KINDS and campaign_total is not None:
                update_progress(
                    last_completed,
                    campaign_total,
                    event.phase,
                    event.message,
                    event.kind,
                    event.reason,
                )

        yield observe


def _candidate_breakdown(report: DiscoveryCampaignReport) -> dict[str, int]:
    counts = Counter(item.kind.value for item in report.proposals)
    return {key: counts[key] for key in sorted(counts)}


def _candidate_summary(counts: Mapping[str, int]) -> str:
    labels = {
        "whole_body": ("whole-body match", "whole-body matches"),
        "private_donor": ("private donor", "private donors"),
        "instruction_mosaic": ("instruction mosaic", "instruction mosaics"),
    }
    if not counts:
        return "none"
    phrases = []
    for kind, count in counts.items():
        singular, plural = labels.get(
            kind,
            (kind.replace("_", " "), f"{kind.replace('_', ' ')}s"),
        )
        phrases.append(f"{count:,} {singular if count == 1 else plural}")
    return " · ".join(phrases)


def _publish_reports(
    *,
    paths: _DiscoveryPaths,
    report: DiscoveryCampaignReport,
    input_receipts: Mapping[str, str],
    output: CLIOutput,
) -> None:
    from reprobit.discovery_report_html import render_discovery_report_html

    report_json = canonical_json(report)
    report_html = render_discovery_report_html(
        report,
        canonical_json_name=paths.report_json.name,
    ).encode("utf-8")
    transaction = CASTransaction(paths.root)
    transaction.write(paths.report_json, report_json)
    transaction.write(paths.report_html, report_html)
    for relative, digest in sorted(input_receipts.items()):
        transaction.assert_unchanged(relative, expected_sha256=digest)
    transaction_result = transaction.commit()
    breakdown = _candidate_breakdown(report)
    message = "\n".join(
        (
            "Discovery review is ready",
            f"  Cells: {report.cells_built:,} built · {report.cells_cached:,} reused",
            f"  Candidates: {_candidate_summary(breakdown)}",
            "  Reports:",
            f"    HTML review: {paths.report_html}",
            f"    Canonical JSON: {paths.report_json}",
            "Nothing was applied. Review candidates before adding anything to a verified project.",
        )
    )
    output.emit(
        "discovery_complete",
        message,
        report_json=paths.report_json,
        report_html=paths.report_html,
        cells=report.cells_total,
        built=report.cells_built,
        reused=report.cells_cached,
        proposals=len(report.proposals),
        candidate_kinds=breakdown,
        applied=False,
        report_json_digest=Digest.from_bytes(report_json),
        report_html_digest=Digest.from_bytes(report_html),
        transaction_id=transaction_result.transaction_id,
    )


def _load_campaign_inputs(paths: _DiscoveryPaths) -> _CampaignInputs:
    from reprobit.discovery_contracts import DiscoveryInputReceipt, DiscoveryInputRole
    from reprobit.msvc_discovery import MsvcDiscoveryRequest
    from reprobit.msvc_discovery_coff import MsvcFunctionReference
    from reprobit.secure_path_contracts import SecurePathError
    from reprobit.secure_paths import read_relative_file
    from reprobit.strict_json import strict_loads

    try:
        request_bytes, request_snapshot = read_relative_file(paths.root, paths.request.name)
    except SecurePathError as exc:
        raise CLIError(f"discovery request is redirected or unstable: {paths.request}") from exc
    request = MsvcDiscoveryRequest.model_validate_json(canonical_json(strict_loads(request_bytes)))
    input_paths = (
        paths.request.name,
        request.source,
        *(item.object for item in request.references),
        *(item.object for item in request.seeds),
    )
    folded_paths: dict[str, str] = {}
    for logical_path in input_paths:
        prior_path = folded_paths.setdefault(logical_path.casefold(), logical_path)
        if prior_path != logical_path:
            raise CLIError(
                "discovery inputs alias under case-insensitive path rules: "
                f"{prior_path} and {logical_path}"
            )
    state_folded = _folded(paths.state)
    state_inputs = tuple(
        logical_path
        for folded, logical_path in folded_paths.items()
        if folded == state_folded or folded.startswith(state_folded + "/")
    )
    if state_inputs:
        raise CLIError(
            "discovery state directory contains campaign input: "
            + ", ".join(sorted(state_inputs, key=str.casefold))
        )
    for report_path in (paths.report_json, paths.report_html):
        if _folded(report_path) in folded_paths:
            raise CLIError("discovery report path overlaps a campaign input")

    receipts: dict[str, str] = {paths.request.name: request_snapshot.digest.value}
    report_inputs = [
        DiscoveryInputReceipt(
            role=DiscoveryInputRole.REQUEST,
            logical_path=paths.request.name,
            digest=request_snapshot.digest,
            size=request_snapshot.size,
        )
    ]

    def read_input(
        relative: str,
        role: DiscoveryInputRole,
        symbol: str | None = None,
    ) -> bytes:
        try:
            payload, snapshot = read_relative_file(paths.root, relative)
        except SecurePathError as exc:
            raise CLIError(
                f"discovery input is absent, redirected, or unstable: {relative}"
            ) from exc
        prior = receipts.setdefault(relative, snapshot.digest.value)
        if prior != snapshot.digest.value:
            raise CLIError(f"discovery input changed while read: {relative}")
        report_inputs.append(
            DiscoveryInputReceipt(
                role=role,
                logical_path=relative,
                digest=snapshot.digest,
                size=snapshot.size,
                symbol=symbol,
            )
        )
        return payload

    source = read_input(request.source, DiscoveryInputRole.SOURCE)
    references = tuple(
        MsvcFunctionReference.from_object(
            read_input(item.object, DiscoveryInputRole.REFERENCE, item.symbol),
            item.symbol,
        )
        for item in request.references
    )
    seeds = {
        item.symbol: read_input(item.object, DiscoveryInputRole.SEED, item.symbol)
        for item in request.seeds
    }
    return _CampaignInputs(
        request=request,
        source=source,
        references=references,
        seeds=seeds,
        receipts=receipts,
        report_inputs=tuple(
            sorted(
                report_inputs,
                key=lambda item: (
                    item.role.value,
                    item.symbol or "",
                    item.logical_path,
                ),
            )
        ),
        folded_paths=folded_paths,
    )


def _prepare_state_roots(paths: _DiscoveryPaths) -> tuple[Path, Path]:
    from reprobit.discovery import require_discovery_directory
    from reprobit.discovery_contracts import DiscoveryError

    try:
        state_root = require_discovery_directory(
            paths.root / paths.state,
            label="discovery state",
        )
        runtime_root = require_discovery_directory(
            state_root / "runtime",
            label="discovery runtime state",
        )
    except DiscoveryError as exc:
        raise CLIError(str(exc)) from exc
    return state_root, runtime_root


def _execute_campaign(
    *,
    args: argparse.Namespace,
    output: CLIOutput,
    paths: _DiscoveryPaths,
    inputs: _CampaignInputs,
    state_root: Path,
    runtime_root: Path,
) -> DiscoveryCampaignReport:
    from reprobit.discovery import DiscoveryCampaignRunner
    from reprobit.msvc_compile import DirectMsvcCompiler
    from reprobit.msvc_discovery import MsvcDiscoveryAdapter
    from reprobit.toolchains import MSVC_42, ClassicMSVCToolchain
    from reprobit.user_config import resolve_toolchain_root

    toolchain_root = resolve_toolchain_root(MSVC_42, args.toolchain_root)
    installation = ClassicMSVCToolchain(MSVC_42, toolchain_root)
    runtime = _configure_runtime(
        args=args,
        installation=installation,
        toolchain_root=toolchain_root,
        runtime_root=runtime_root,
    )
    with output.activity(
        "fingerprinting the current MSVC 4.2 toolchain",
        phase="discovery-toolchain",
    ):
        toolchain_lock = installation.create_lock(
            include_trees=True,
            runtime_paths=runtime.runtime_paths,
        )
    toolchain_authority = Digest.from_bytes(canonical_json(toolchain_lock))

    def probe_toolchain() -> Digest:
        installation.doctor(toolchain_lock).require_ok()
        return toolchain_authority

    compiler = DirectMsvcCompiler.create(
        wrapper=runtime.driver,
        arguments=inputs.request.compiler_arguments,
        environment=runtime.environment,
        toolchain_authority=toolchain_authority,
        support_files=runtime.support_files,
        toolchain_authority_probe=probe_toolchain,
        timeout_seconds=args.compile_timeout,
        parallelism=runtime.compiler_parallelism,
    )
    adapter = MsvcDiscoveryAdapter(
        source=inputs.source,
        compiler=compiler,
        references=inputs.references,
        seed_objects=inputs.seeds,
    )
    wine_lifecycle = (
        _discovery_wineserver_lifecycle(
            executable=runtime.wineserver,
            runtime_root=runtime_root,
            environment=runtime.environment,
            timeout_seconds=args.cleanup_timeout,
        )
        if runtime.wineserver is not None
        else nullcontext()
    )
    with wine_lifecycle, _campaign_progress(output) as observe_progress:
        return DiscoveryCampaignRunner(
            state_root=state_root / "cache",
            workspace_root=state_root / "runs",
            adapter=adapter,
            jobs=args.jobs,
            artifact_path_prefix=f"{paths.state.as_posix()}/cache/artifacts",
            input_receipts=inputs.report_inputs,
            progress=observe_progress,
        ).run(inputs.request.plan)


def _validate_selected_artifacts(
    *,
    paths: _DiscoveryPaths,
    report: DiscoveryCampaignReport,
    inputs: _CampaignInputs,
) -> None:
    from reprobit.secure_path_contracts import SecurePathError
    from reprobit.secure_paths import read_relative_file

    for artifact in report.artifacts:
        try:
            payload, snapshot = read_relative_file(paths.root, artifact.logical_path)
        except SecurePathError as exc:
            raise CLIError(
                f"discovery artifact is absent, redirected, or unstable: {artifact.logical_path}"
            ) from exc
        if len(payload) != artifact.object_size or snapshot.digest != artifact.object:
            raise CLIError(f"discovery artifact differs from its report: {artifact.logical_path}")
        prior = inputs.receipts.setdefault(artifact.logical_path, snapshot.digest.value)
        if prior != snapshot.digest.value:
            raise CLIError(
                f"discovery artifact path has conflicting receipts: {artifact.logical_path}"
            )
        prior_path = inputs.folded_paths.setdefault(
            artifact.logical_path.casefold(),
            artifact.logical_path,
        )
        if prior_path != artifact.logical_path:
            raise CLIError(
                "discovery artifact aliases a campaign input under case-insensitive path rules: "
                f"{prior_path} and {artifact.logical_path}"
            )
    for report_path in (paths.report_json, paths.report_html):
        if _folded(report_path) in inputs.folded_paths:
            raise CLIError("discovery report path overlaps a campaign input")


def command_discover(args: argparse.Namespace, output: CLIOutput) -> int:
    """Run one non-certifying, preview-only MSVC 4.2 discovery campaign."""
    from reprobit.state_lock import AdvisoryFileLock

    paths = _resolve_paths(args)
    inputs = _load_campaign_inputs(paths)
    state_root, runtime_root = _prepare_state_roots(paths)
    session_lock = AdvisoryFileLock(runtime_root / "session.lock")
    if not session_lock.acquire(nonblocking=True):
        session_lock.close()
        raise CLIError(f"another discovery campaign owns {state_root}")
    try:
        report = _execute_campaign(
            args=args,
            output=output,
            paths=paths,
            inputs=inputs,
            state_root=state_root,
            runtime_root=runtime_root,
        )
        _validate_selected_artifacts(paths=paths, report=report, inputs=inputs)
        _publish_reports(
            paths=paths,
            report=report,
            input_receipts=inputs.receipts,
            output=output,
        )
        return 0
    finally:
        session_lock.close()


__all__ = ["command_discover"]
