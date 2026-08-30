"""Short, human-first environment setup commands."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath

from reprobit.backends import (
    ExecutionBackend,
)
from reprobit.cli_environment import selected_backend
from reprobit.cli_output import CLIOutput
from reprobit.cli_paths import CLIError, project_root, relative_output, safe_project_path
from reprobit.msvc42_provision import provision_msvc42, verify_msvc42
from reprobit.project_loader import load_project
from reprobit.project_readiness import inspect_project_readiness, render_project_readiness
from reprobit.schema import ToolchainLock as SchemaToolchainLock
from reprobit.strict_json import canonical_json, strict_load
from reprobit.toolchains import MSVC_42, ClassicMSVCToolchain, validate_toolchain_lock
from reprobit.transactions import CASTransaction
from reprobit.user_config import (
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
    ):
        return provision_msvc42(destination)


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
    output.emit(
        "toolchain_provisioned",
        f"Compiler ready at {installed}\nNext: rbit setup",
        profile=args.profile,
        root=installed,
        saved=not args.no_save,
        next_command="rbit setup",
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


def command_doctor(args: argparse.Namespace, output: CLIOutput) -> int:
    """Check the selected execution backend and optional compiler installation."""

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
    project = Path(args.project).expanduser().resolve(strict=False)
    if (project / "reprobit.toml").is_file():
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
        if args.toolchain_root is not None:
            installation = ClassicMSVCToolchain(
                spec.toolchain.profile,
                Path(args.toolchain_root).expanduser().resolve(strict=True),
            )
            lock_document = None
            lock_path = safe_project_path(project, spec.toolchain.lock_file)
            if lock_path.is_file():
                lock_document = SchemaToolchainLock.model_validate_json(
                    canonical_json(strict_load(lock_path))
                )
            tool_report = installation.doctor(lock_document)
            okay = okay and tool_report.ok
            for tool_check in tool_report.checks:
                output.emit(
                    "doctor_check",
                    f"{'ok' if tool_check.passed else 'FAIL'} "
                    f"toolchain/{tool_check.path}: {tool_check.detail}",
                    component="toolchain",
                    name=tool_check.path,
                    passed=tool_check.passed,
                    detail=tool_check.detail,
                )
    elif args.toolchain_root is not None:
        if args.toolchain_profile is None:
            raise CLIError("--toolchain-root requires --toolchain-profile without a project")
        installation = ClassicMSVCToolchain(
            args.toolchain_profile,
            Path(args.toolchain_root).expanduser().resolve(strict=True),
        )
        tool_report = installation.doctor()
        okay = okay and tool_report.ok
        for tool_check in tool_report.checks:
            output.emit(
                "doctor_check",
                f"{'ok' if tool_check.passed else 'FAIL'} "
                f"toolchain/{tool_check.path}: {tool_check.detail}",
                component="toolchain",
                name=tool_check.path,
                passed=tool_check.passed,
                detail=tool_check.detail,
            )
    output.emit(
        "doctor_result",
        "doctor checks passed" if okay else "doctor checks failed",
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
        resolve_toolchain_root(identifier, args.root),
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
    relative = relative_output(root, args.output or default_output)
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
        raise CLIError(f"no ReproBit project found; run `rbit init {root}` first")
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
    if not args.no_save:
        save_toolchain_root(spec.toolchain.profile, selected_root)

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
    readiness = inspect_project_readiness(root)
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
        readiness=readiness.items,
        next_command=readiness.next_command,
    )
    return 0 if not failures else 1


__all__ = [
    "command_doctor",
    "command_setup",
    "command_toolchain_lock",
    "command_toolchain_provision",
]
