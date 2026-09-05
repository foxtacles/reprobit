"""Short, human-first environment setup commands."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath

from reprobit.backends import (
    ExecutionBackend,
)
from reprobit.cli_environment import selected_backend
from reprobit.cli_output import CLIOutput, NextStep, human_command, next_step_fields
from reprobit.cli_paths import (
    CLIError,
    paths_overlap,
    project_root,
    protected_project_paths,
    relative_output,
    safe_project_path,
)
from reprobit.msvc42_provision import provision_msvc42, verify_msvc42
from reprobit.project_loader import load_project
from reprobit.project_readiness import inspect_project_readiness, render_project_readiness
from reprobit.schema import SourceManifestDocument
from reprobit.schema import ToolchainLock as SchemaToolchainLock
from reprobit.strict_json import canonical_json, strict_load
from reprobit.toolchains import (
    MSVC_42,
    ClassicMSVCToolchain,
    ToolchainDoctorReport,
    ToolchainError,
    validate_toolchain_lock,
)
from reprobit.transactions import CASTransaction
from reprobit.user_config import (
    UserConfigError,
    default_toolchain_root,
    resolve_toolchain_root,
    save_toolchain_root,
)

_CROSS_HOST_TRANSPORTS = (
    "wine/x86/cl",
    "wine/x86/rc",
    "wine/x86/link",
    "wine/x86/lib",
    "wine/x86/wine-msvc.sh",
)


def _provision(
    *,
    profile: str,
    destination: Path,
    output: CLIOutput,
) -> Path:
    if profile != MSVC_42:
        raise CLIError(
            "automatic acquisition is currently available only for Microsoft Visual C++ 4.2; "
            "provide an existing installation with --toolchain-root"
        )
    with output.activity(
        "downloading and authenticating Microsoft Visual C++ 4.2",
        phase="toolchain-provision",
    ) as progress:
        return provision_msvc42(destination, progress=progress)


def command_toolchain_provision(args: argparse.Namespace, output: CLIOutput) -> int:
    """Install or re-authenticate one finite external compiler payload."""

    destination = (
        Path(args.destination).expanduser().resolve(strict=False)
        if args.destination is not None
        else default_toolchain_root(args.profile)
    )
    installed = _provision(
        profile=args.profile,
        destination=destination,
        output=output,
    )
    if not args.no_save:
        save_toolchain_root(args.profile, installed)
    next_step = NextStep(("rbit", "setup", "."))
    output.emit(
        "toolchain_provisioned",
        f"Compiler ready at {installed}\nNext in a ReproBit project: {next_step.command}",
        profile=args.profile,
        root=installed,
        saved=not args.no_save,
        **next_step.fields(),
    )
    return 0


def _load_toolchain_lock(path: Path) -> SchemaToolchainLock:
    document = SchemaToolchainLock.model_validate_json(canonical_json(strict_load(path)))
    validate_toolchain_lock(document)
    return document


def _create_project_lock(
    *,
    root: Path,
    profile: str,
    installation: ClassicMSVCToolchain,
    lock_path: Path,
) -> SchemaToolchainLock:
    runtime_paths: tuple[str, ...] = ()
    if profile == MSVC_42:
        present = tuple(
            relative
            for relative in _CROSS_HOST_TRANSPORTS
            if installation.host_path(relative).is_file()
        )
        if present and present != _CROSS_HOST_TRANSPORTS:
            missing = sorted(set(_CROSS_HOST_TRANSPORTS) - set(present))
            raise CLIError(
                "the MSVC 4.2 transport installation is incomplete; missing " + ", ".join(missing)
            )
        runtime_paths = present
    document = installation.create_lock(include_trees=True, runtime_paths=runtime_paths)
    relative = lock_path.relative_to(root)
    transaction = CASTransaction(root)
    transaction.write(relative, canonical_json(document), expected_sha256=None)
    transaction.commit()
    return document


def _backend_failures(backend: ExecutionBackend, *, execute_probe: bool) -> tuple[str, ...]:
    report = backend.doctor(execute_probe=execute_probe)
    return tuple(
        f"{check.name}: {check.detail}"
        for check in report.checks
        if check.required and not check.passed
    )


def _emit_toolchain_report(output: CLIOutput, report: ToolchainDoctorReport) -> None:
    for check in report.checks:
        output.emit(
            "doctor_check",
            f"{'ok' if check.passed else 'FAIL'} toolchain/{check.path}: {check.detail}",
            component="toolchain",
            name=check.path,
            passed=check.passed,
            detail=check.detail,
        )


def _emit_doctor_failure(
    output: CLIOutput,
    *,
    component: str,
    name: str,
    detail: str,
) -> None:
    output.emit(
        "doctor_check",
        f"FAIL {component}/{name}: {detail}",
        component=component,
        name=name,
        passed=False,
        required=True,
        detail=detail,
    )


def command_doctor(args: argparse.Namespace, output: CLIOutput) -> int:
    """Check the selected backend and the compiler selected for this project."""

    backend = selected_backend(args)
    report = backend.doctor(execute_probe=args.execute_probe)
    okay = report.ok
    for backend_check in report.checks:
        output.emit(
            "doctor_check",
            f"{'ok' if backend_check.passed else 'FAIL'} "
            f"backend/{backend_check.name}: {backend_check.detail}",
            component="backend",
            name=backend_check.name,
            passed=backend_check.passed,
            required=backend_check.required,
            detail=backend_check.detail,
        )
    project = (
        Path(args.project).expanduser().resolve(strict=False) if args.project is not None else None
    )
    if project is not None:
        entrypoint = project / "reprobit.toml"
        if entrypoint.is_symlink() or not entrypoint.is_file():
            raise CLIError(f"no ReproBit project found at {entrypoint}")
        spec = load_project(project)
        if args.toolchain_profile is not None and args.toolchain_profile != spec.toolchain.profile:
            raise CLIError(
                "requested toolchain profile differs from reprobit.toml: "
                f"{args.toolchain_profile} != {spec.toolchain.profile}"
            )
        output.emit(
            "doctor_check",
            f"ok project/schema: {spec.project_id}",
            component="project",
            name="schema",
            passed=True,
        )
        try:
            selected_root = resolve_toolchain_root(
                spec.toolchain.profile,
                args.toolchain_root,
            )
        except (OSError, UserConfigError) as error:
            _emit_doctor_failure(
                output,
                component="toolchain",
                name="root",
                detail=str(error),
            )
            okay = False
        else:
            installation = ClassicMSVCToolchain(
                spec.toolchain.profile,
                selected_root,
            )
            lock_path = safe_project_path(project, spec.toolchain.lock_file)
            if lock_path.is_symlink() or not lock_path.is_file():
                _emit_doctor_failure(
                    output,
                    component="project",
                    name="toolchain-lock",
                    detail=f"saved compiler lock is missing: {lock_path}",
                )
                okay = False
            else:
                try:
                    lock_document = _load_toolchain_lock(lock_path)
                except (OSError, ToolchainError, ValueError) as error:
                    _emit_doctor_failure(
                        output,
                        component="project",
                        name="toolchain-lock",
                        detail=f"saved compiler lock is invalid: {error}",
                    )
                    okay = False
                else:
                    try:
                        tool_report = installation.doctor(lock_document)
                    except (OSError, ToolchainError) as error:
                        _emit_doctor_failure(
                            output,
                            component="toolchain",
                            name="root",
                            detail=f"compiler could not be checked: {error}",
                        )
                        okay = False
                    else:
                        okay = okay and tool_report.ok
                        _emit_toolchain_report(output, tool_report)
    elif args.toolchain_profile is not None or args.toolchain_root is not None:
        if args.toolchain_profile is None:
            raise CLIError("--toolchain-root requires --profile without a project")
        try:
            selected_root = resolve_toolchain_root(
                args.toolchain_profile,
                args.toolchain_root,
            )
            installation = ClassicMSVCToolchain(args.toolchain_profile, selected_root)
            tool_report = installation.doctor()
        except (OSError, ToolchainError, UserConfigError) as error:
            _emit_doctor_failure(
                output,
                component="toolchain",
                name="root",
                detail=f"compiler could not be checked: {error}",
            )
            okay = False
        else:
            okay = okay and tool_report.ok
            _emit_toolchain_report(output, tool_report)
    if project is None and args.toolchain_profile is None and args.toolchain_root is None:
        message = (
            "host checks passed; no project compiler was checked"
            if okay
            else "host checks failed; no project compiler was checked"
        )
    else:
        message = "doctor checks passed" if okay else "doctor checks failed"
    output.emit(
        "doctor_result",
        message,
        passed=okay,
        backend=backend.identifier,
        executed_probe=report.executed_probe,
    )
    return 0 if okay else 1


def command_toolchain_lock(args: argparse.Namespace, output: CLIOutput) -> int:
    """Record the exact compiler installation used by a project."""

    root = project_root(args.project)
    config_path = root / "reprobit.toml"
    spec = load_project(config_path) if config_path.is_file() else None
    identifier = args.profile or (spec.toolchain.profile if spec is not None else None)
    if identifier is None:
        raise CLIError("toolchain profile is required without reprobit.toml")
    installation = ClassicMSVCToolchain(
        identifier,
        resolve_toolchain_root(identifier, args.toolchain_root),
    )
    with output.activity("checking compiler files, headers, and libraries"):
        document = installation.create_lock(
            include_trees=True,
            runtime_paths=args.runtime_file,
        )
    data = canonical_json(document)
    default_output = (
        spec.toolchain.lock_file if spec is not None else "reprobit/toolchain.lock.json"
    )
    if spec is not None:
        configured_output = relative_output(root, default_output)
        if args.output is not None and relative_output(root, args.output) != configured_output:
            raise CLIError(
                "--output cannot change an existing project's configured compiler lock path"
            )
        relative = configured_output
    else:
        relative = relative_output(root, args.output or default_output)
    absolute_output = root / relative
    if spec is not None:
        source_paths: tuple[str, ...] = ()
        source_manifest_path = safe_project_path(root, spec.layout.source_manifest)
        if source_manifest_path.is_file():
            try:
                source_manifest = SourceManifestDocument.model_validate_json(
                    canonical_json(strict_load(source_manifest_path))
                )
            except (OSError, ValueError) as error:
                raise CLIError(
                    f"cannot validate existing source manifest: {source_manifest_path}"
                ) from error
            source_paths = tuple(entry.path for entry in source_manifest.entries)
        for label, protected in protected_project_paths(
            root,
            spec,
            source_paths=source_paths,
        ):
            if label == "compiler lock":
                continue
            if paths_overlap(absolute_output, protected):
                raise CLIError(f"compiler lock output overlaps {label}: {protected}")
    transaction = CASTransaction(root)
    transaction.write(relative, data)
    result = transaction.commit()
    output.emit(
        "toolchain_locked",
        f"locked {identifier} to {relative}",
        profile=identifier,
        output=relative,
        tools=len(document.tools),
        runtime_files=len(document.runtime_files),
        input_trees=len(document.input_trees),
        transaction_id=result.transaction_id,
    )
    return 0


def command_setup(args: argparse.Namespace, output: CLIOutput) -> int:
    """Prepare this machine for one project without inventing project authority."""

    root = project_root(args.project)
    entrypoint = root / "reprobit.toml"
    if not entrypoint.is_file() or entrypoint.is_symlink():
        command = human_command(("rbit", "init", root))
        raise CLIError(f"no ReproBit project found; run {command} first")
    spec = load_project(entrypoint)
    selected_root = resolve_toolchain_root(
        spec.toolchain.profile,
        args.toolchain_root,
        require=False,
    )
    if not selected_root.is_dir():
        if args.no_provision:
            raise CLIError(
                f"compiler is not installed at {selected_root}; rerun without --no-provision"
            )
        selected_root = _provision(
            profile=spec.toolchain.profile,
            destination=selected_root,
            output=output,
        )
    if spec.toolchain.profile == MSVC_42:
        with output.activity("authenticating the compiler installation", phase="toolchain-check"):
            verify_msvc42(selected_root)
    installation = ClassicMSVCToolchain(spec.toolchain.profile, selected_root)
    lock_path = safe_project_path(root, spec.toolchain.lock_file)
    if lock_path.is_symlink():
        raise CLIError(f"toolchain lock is redirected: {lock_path}")
    created_lock = False
    if lock_path.is_file():
        lock_document = _load_toolchain_lock(lock_path)
    else:
        with output.activity("locking exact compiler files", phase="toolchain-lock"):
            document = _create_project_lock(
                root=root,
                profile=spec.toolchain.profile,
                installation=installation,
                lock_path=lock_path,
            )
        lock_document = document
        created_lock = True
    toolchain_report = installation.doctor(lock_document)
    toolchain_report.require_ok()

    backend = selected_backend(args)
    failures = _backend_failures(backend, execute_probe=not args.skip_probe)
    if not args.no_save and not failures:
        save_toolchain_root(spec.toolchain.profile, selected_root)
    readiness = inspect_project_readiness(
        root,
        check_local_environment=True,
        local_toolchain_root=selected_root,
        prior_toolchain_report=toolchain_report,
        local_backend=backend,
    )
    lines = [
        (
            f"Environment ready for {installation.profile.display_name}"
            if not failures
            else "Environment needs attention"
        ),
        f"Compiler: {selected_root}",
        f"Project lock: {'created' if created_lock else 'matches'}",
    ]
    if failures:
        lines.extend(f"[  ] {failure}" for failure in failures)
    lines.append(render_project_readiness(readiness))
    output.emit(
        "setup",
        "\n".join(lines),
        environment_ready=not failures,
        project_ready=readiness.ready,
        profile=spec.toolchain.profile,
        toolchain_root=selected_root,
        toolchain_lock=PurePosixPath(spec.toolchain.lock_file),
        toolchain_lock_created=created_lock,
        backend=backend.identifier,
        backend_failures=failures,
        readiness=[
            {
                "id": item.id,
                "label": item.label,
                "ready": item.ready,
                "detail": item.detail,
                "next_command": item.next_command,
                "next_argv": item.next_argv,
            }
            for item in readiness.items
        ],
        next_instruction=readiness.next_instruction,
        **next_step_fields(readiness.next),
    )
    return 0 if not failures else 1


__all__ = [
    "command_doctor",
    "command_setup",
    "command_toolchain_lock",
    "command_toolchain_provision",
]
