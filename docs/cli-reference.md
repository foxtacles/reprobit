# rbit command reference

Generated from the argparse tree by `python -m reprobit.cli_reference`;
`tests/test_cli_reference.py` fails when this file is stale. Commands appear
in parser order. [docs/cli.md](cli.md) explains the workflow around them.

## Global options

| Argument | Default | Description |
|---|---|---|
| `--version` | | show the program version and exit |
| `--format` `{text,ndjson}` | `text` | human-readable text or stable machine events; accepted before or after the sub-command |
| `--quiet` | | silence text-mode progress (phase starts, heartbeats, unit counts); results, warnings and errors still print; ndjson output is unchanged; accepted before or after the sub-command |

Every command also accepts `-h`/`--help`. The exit-status contract is in
[docs/cli.md](cli.md#exit-status).

## Commands

### `rbit init`

Start a ReproBit project.

```
rbit init [-h] [--project-id PROJECT_ID] [--profile {msvc_4_2,msvc_5_0_rtm,msvc_5_0_sp1,msvc_5_0_sp2,msvc_5_0_sp3}] [--target NAME] [--artifact [TARGET=]PATH] [--oracle [TARGET=]PATH] [--logical-source DOS_PATH] [--logical-build DOS_PATH] [--logical-toolchain DOS_PATH] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

| Argument | Default | Description |
|---|---|---|
| `--project-id` `PROJECT_ID` |  | portable project name (default: derive it from the directory) |
| `--profile` `{msvc_4_2,msvc_5_0_rtm,msvc_5_0_sp1,msvc_5_0_sp2,msvc_5_0_sp3}` | `msvc_4_2` | compiler profile (default: msvc_4_2) |
| `--target` `NAME` |  | target name (repeatable; default: program) |
| `--artifact` `[TARGET=]PATH` |  | rebuilt output path for one target, or TARGET=PATH when repeated (default: build/TARGET.exe) |
| `--oracle` `[TARGET=]PATH` |  | original/reference path for one target, or TARGET=PATH when repeated (default: reference/TARGET.exe) |

**advanced logical path options**

Compiler-visible DOS paths recorded in reprobit.toml; every run maps its private source, output, and toolchain trees to exactly these spellings.

| Argument | Default | Description |
|---|---|---|
| `--logical-source` `DOS_PATH` | `R:\source` | compiler-visible root of the source tree (default: R:\source) |
| `--logical-build` `DOS_PATH` | `R:\build` | compiler-visible root of the build output tree (default: R:\build) |
| `--logical-toolchain` `DOS_PATH` | `R:\toolchain` | compiler-visible root of the compiler installation (default: R:\toolchain) |

### `rbit setup`

Prepare the compiler and this machine for a project.

```
rbit setup [-h] [--toolchain-root DIRECTORY] [--no-provision] [--no-save] [--skip-probe] [--backend {auto,posix_wine_v1,windows_native_v1}] [--wine PATH_OR_NAME] [--wineserver PATH_OR_NAME] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

| Argument | Default | Description |
|---|---|---|
| `--toolchain-root` `DIRECTORY` |  | compiler installation override (normally remembered by rbit setup) |
| `--no-provision` |  | fail instead of downloading a missing supported compiler |
| `--no-save` |  | do not remember this machine's compiler location |
| `--skip-probe` |  | skip the bounded execution probe (faster, but less complete) |

**advanced host options**

| Argument | Default | Description |
|---|---|---|
| `--backend` `{auto,posix_wine_v1,windows_native_v1}` | `auto` | execution backend (default: select from the host platform) |
| `--wine` `PATH_OR_NAME` | `wine` | POSIX Wine executable (default: wine from PATH) |
| `--wineserver` `PATH_OR_NAME` | `wineserver` | POSIX wineserver executable (default: wineserver from PATH) |

### `rbit doctor`

Check this machine's backend and the selected compiler files.

```
rbit doctor [-h] [--backend {auto,posix_wine_v1,windows_native_v1}] [--wine PATH_OR_NAME] [--wineserver PATH_OR_NAME] [--execute-probe] [--profile {msvc_4_2,msvc_5_0_rtm,msvc_5_0_sp1,msvc_5_0_sp2,msvc_5_0_sp3}] [--toolchain-root DIRECTORY] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` |  | project directory; omit it to check only this machine |

| Argument | Default | Description |
|---|---|---|
| `--backend` `{auto,posix_wine_v1,windows_native_v1}` | `auto` | execution backend (default: select from the host platform) |
| `--wine` `PATH_OR_NAME` | `wine` | POSIX Wine executable (default: wine from PATH) |
| `--wineserver` `PATH_OR_NAME` | `wineserver` | POSIX wineserver executable (default: wineserver from PATH) |
| `--execute-probe` |  | also run the bounded backend and isolation probe (including Wine when used) |
| `--profile` `{msvc_4_2,msvc_5_0_rtm,msvc_5_0_sp1,msvc_5_0_sp2,msvc_5_0_sp3}` |  | compiler profile when checking an installation without a project |
| `--toolchain-root` `DIRECTORY` |  | compiler installation to authenticate (default: use the project's remembered compiler when available) |

### `rbit toolchain provision`

Download and authenticate a supported compiler.

```
rbit toolchain provision [-h] [--destination DIRECTORY] [--no-save] [{msvc_4_2}]
```

| Argument | Default | Description |
|---|---|---|
| `profile` `{msvc_4_2}` | `msvc_4_2` | compiler profile (default: msvc_4_2) |

| Argument | Default | Description |
|---|---|---|
| `--destination` `DIRECTORY` |  | installation directory (default: this platform's standard user location) |
| `--no-save` |  | do not remember the installed compiler location |

### `rbit toolchain lock`

Record the exact compiler files this project expects.

```
rbit toolchain lock [-h] [--profile {msvc_4_2,msvc_5_0_rtm,msvc_5_0_sp1,msvc_5_0_sp2,msvc_5_0_sp3}] [--toolchain-root DIRECTORY] [--runtime-file RELATIVE_PATH] [--output PROJECT_RELATIVE_PATH] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

| Argument | Default | Description |
|---|---|---|
| `--profile` `{msvc_4_2,msvc_5_0_rtm,msvc_5_0_sp1,msvc_5_0_sp2,msvc_5_0_sp3}` |  | compiler profile (default: read it from reprobit.toml) |
| `--toolchain-root` `DIRECTORY` |  | compiler installation override (normally remembered by rbit setup) |
| `--runtime-file` `RELATIVE_PATH` |  | pin an additional wrapper or runtime dependency (repeatable) |
| `--output` `PROJECT_RELATIVE_PATH` |  | lock-file path without reprobit.toml (existing projects always use their configured path) |

### `rbit source preview`

Show source changes and records that need review without writing.

```
rbit source preview [-h] [--path PATH] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

| Argument | Default | Description |
|---|---|---|
| `--path` `PATH` |  | project-relative file or tree to inspect (repeatable; defaults to Git tracked files) |

### `rbit source export`

Write the reviewed effective source view used by compilers and analysis tools.

```
rbit source export [-h] [--destination PROJECT_RELATIVE_DIRECTORY] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

| Argument | Default | Description |
|---|---|---|
| `--destination` `PROJECT_RELATIVE_DIRECTORY` | `build/reprobit-source` | directory to create or refresh (default: build/reprobit-source) |

### `rbit source lock`

Safely record tracked or explicitly named source inputs.

```
rbit source lock [-h] [--path PATH] [--invalidate-producer-graph] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

| Argument | Default | Description |
|---|---|---|
| `--path` `PATH` |  | project-relative file or tree to admit (repeatable; defaults to Git tracked files) |
| `--invalidate-producer-graph` |  | remove a stale generated graph in the same transaction after source changes |

### `rbit source regenerate`

Advanced maintenance tool. After editing an existing project file, normally run rbit repair . instead. This command only previews or applies the saved source-record updates; it does not build or verify the project.

```
rbit source regenerate [-h] [--apply] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

| Argument | Default | Description |
|---|---|---|
| `--apply` |  | save the changes shown by the preview (default: preview without writing) |

### `rbit import cmake`

Prepare and record an ordinary CMake project in one guided run.

```
rbit import cmake [-h] [--target TARGET=CMAKE_TARGET] [--refresh] [--path PATH] [--keep-workspace {never,on-failure,always}] [--toolchain-root DIRECTORY] [--compiler-transport PATH] [--resource-transport PATH] [--cmake PATH_OR_NAME] [--configuration CONFIGURATION] [--cmake-define NAME=VALUE | --clear-cmake-defines] [--timeout SECONDS] [--directive-input TARGET=LIBRARY | --clear-directive-inputs] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

| Argument | Default | Description |
|---|---|---|
| `--target` `TARGET=CMAKE_TARGET` |  | map a ReproBit target during the first import (not used by --refresh) |
| `--refresh` |  | update the saved source list and CMake build records as one verified change |
| `--path` `PATH` |  | source file or directory selected by --refresh (repeatable; default: Git index) |
| `--keep-workspace` `{never,on-failure,always}` | `on-failure` | retain temporary import files: never, on-failure (default), or always |

**advanced host and graph options**

| Argument | Default | Description |
|---|---|---|
| `--toolchain-root` `DIRECTORY` |  | compiler installation override (normally remembered by rbit setup) |
| `--compiler-transport` `PATH` |  | POSIX transport selector for the locked compiler (paired with --resource-transport) |
| `--resource-transport` `PATH` |  | POSIX transport selector for the locked resource compiler |
| `--cmake` `PATH_OR_NAME` |  | CMake executable (default: resolve cmake from PATH) |
| `--configuration` `CONFIGURATION` |  | single-configuration CMake build type (default: RelWithDebInfo) |
| `--cmake-define` `NAME=VALUE` |  | set one CMake cache value (repeatable) |
| `--clear-cmake-defines` |  | replace saved CMake cache values with an empty list during --refresh |
| `--timeout` `SECONDS` |  | bounded configure deadline (default: 600) |
| `--directive-input` `TARGET=LIBRARY` |  | record one prelink-discovered default library edge (repeatable) |
| `--clear-directive-inputs` |  | replace saved default-library edges with an empty list during --refresh |

### `rbit graph configure`

Create a fresh CMake metadata tree without building.

```
rbit graph configure [-h] --workspace-root EMPTY_DIRECTORY --toolchain-root DIRECTORY --compiler-transport PATH --resource-transport PATH [--cmake PATH_OR_NAME] [--configuration CONFIGURATION] [--cmake-define NAME=VALUE] [--timeout SECONDS] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

| Argument | Default | Description |
|---|---|---|
| `--workspace-root` `EMPTY_DIRECTORY` | required | new or empty workspace that will receive fixed source/ and build/ trees |
| `--toolchain-root` `DIRECTORY` | required | physical root of the locally provisioned locked toolchain |
| `--compiler-transport` `PATH` | required | admitted compiler frontend used only for CMake feature detection |
| `--resource-transport` `PATH` | required | admitted resource-compiler frontend paired with the compiler transport |
| `--cmake` `PATH_OR_NAME` | `cmake` | CMake executable (default: resolve cmake from PATH) |
| `--configuration` `CONFIGURATION` | `RelWithDebInfo` | single-configuration CMake build type (default: RelWithDebInfo) |
| `--cmake-define` `NAME=VALUE` |  | set one CMake cache value (repeatable) |
| `--timeout` `SECONDS` | `600.0` | bounded configure deadline (default: 600) |

### `rbit graph extract`

Record direct compiler and linker steps from that CMake tree.

```
rbit graph extract [-h] --configured-build-root DIRECTORY --effective-source-root DIRECTORY --effective-source-digest SHA256 --toolchain-root DIRECTORY [--target-plan TARGET_PLAN] [--configuration CONFIGURATION] [--cmake PATH_OR_NAME] [--timeout SECONDS] [--cmake-define NAME=VALUE] [--directive-input TARGET=LIBRARY] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

| Argument | Default | Description |
|---|---|---|
| `--configured-build-root` `DIRECTORY` | required | CMake metadata tree created by rbit graph configure |
| `--effective-source-root` `DIRECTORY` | required | effective source tree whose physical paths match the configured commands |
| `--effective-source-digest` `SHA256` | required | source receipt printed by the matching rbit graph configure run |
| `--toolchain-root` `DIRECTORY` | required | physical root matching the committed logical toolchain seat |
| `--target-plan` `TARGET_PLAN` |  | path beneath the configured build (defaults to reprobit-target-plan.json) |
| `--configuration` `CONFIGURATION` | `RelWithDebInfo` | configuration used by the matching graph configure run |
| `--cmake` `PATH_OR_NAME` | `cmake` | CMake executable used by the matching graph configure run |
| `--timeout` `SECONDS` | `600.0` | configure deadline used by the matching graph configure run |
| `--cmake-define` `NAME=VALUE` |  | CMake cache value used by the matching graph configure run (repeatable) |
| `--directive-input` `TARGET=LIBRARY` |  | commit one prelink-discovered DEFAULTLIB edge; repeat for each target/library |

### `rbit validate`

Check every saved project file.

```
rbit validate [-h] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

### `rbit cost`

Show intervention cost totals.

```
rbit cost [-h] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

### `rbit status`

Show what is ready and the next project setup step.

```
rbit status [-h] [--all] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

| Argument | Default | Description |
|---|---|---|
| `--all` |  | include checks that already pass |

### `rbit clean`

Remove inactive workspaces; cache and reports are opt-in.

```
rbit clean [-h] [--preview] [--older-than-hours HOURS] [--cache | --obsolete-cache] [--reports] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

| Argument | Default | Description |
|---|---|---|
| `--preview` |  | show how much space can be freed without removing anything |
| `--older-than-hours` `HOURS` |  | keep workspace and cache entries newer than this age (default: 0) |
| `--cache` |  | also remove incremental and repair-search cache data selected by age |
| `--obsolete-cache` |  | also remove cache data this ReproBit version cannot reuse; keep the current cache |
| `--reports` |  | also remove the canonical verification and grind reports |

### `rbit explain`

Explain saved interventions.

```
rbit explain [-h] [--intervention ID] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

| Argument | Default | Description |
|---|---|---|
| `--intervention` `ID` |  | show full details for one intervention |

### `rbit repair`

Use this after editing a file in a project that already matched exactly, including a shared header used by many source files. ReproBit repairs the saved build guidance in private, rebuilds, and publishes only after every target matches exactly. For added or removed files, start with source preview; it prints a safe next command when one is available.

```
rbit repair [-h] [--jobs COUNT] [--keep-workspace {never,on-failure,always}] [--backend {auto,posix_wine_v1,windows_native_v1}] [--wine PATH_OR_NAME] [--wineserver PATH_OR_NAME] [--toolchain-root DIRECTORY] [--compiler-transport PATH] [--resource-transport PATH] [--initialization-timeout SECONDS] [--compile-timeout SECONDS] [--link-timeout SECONDS] [--cleanup-timeout SECONDS] [--policy {clean,allow-quarantine}] [--report-dir PROJECT_RELATIVE_DIRECTORY] [--retune-radius DISTANCE] [--retune-candidates COUNT] [--candidate-limit COUNT] [--discovery-candidates COUNT] [--adjustment-rounds COUNT] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

| Argument | Default | Description |
|---|---|---|
| `--jobs` `COUNT` |  | maximum parallel build workers (default: the CPUs this process may use, at most 8) |
| `--keep-workspace` `{never,on-failure,always}` | `on-failure` | keep the private workspace: never, only on failure, or always (default: on-failure) |
| `--policy` `{clean,allow-quarantine}` |  | optionally narrow the project's committed authenticity policy |
| `--report-dir` `PROJECT_RELATIVE_DIRECTORY` |  | write report.json and report.html beneath this project directory |

Shared: see [advanced execution options](#advanced-execution-options).

**search bounds**

Widen the bounded search for larger repairs; a completed repair must still reproduce every expected output in a build from scratch.

| Argument | Default | Description |
|---|---|---|
| `--retune-radius` `DISTANCE` |  | largest declaration-count change tried per saved compiler choice or source layout (default: 8; max: 64) |
| `--retune-candidates` `COUNT` |  | maximum nearby settings tried per saved compiler choice or source layout (default: 64; max: 4096) |
| `--candidate-limit` `COUNT` |  | maximum nearby repair choices tested by the whole command (default: 256; max: 65536) |
| `--discovery-candidates` `COUNT` |  | fresh declaration settings built per affected source file after its saved compiler choices are exhausted (default: 64; max: 2005) |
| `--adjustment-rounds` `COUNT` |  | maximum saved-guidance adjustment rounds before repair stops (default: 24) |

### `rbit build`

Incrementally rebuild changed compiler and linker steps without CMake.

```
rbit build [-h] [--jobs COUNT] [--cold] [--keep-workspace {never,on-failure,always}] [--backend {auto,posix_wine_v1,windows_native_v1}] [--wine PATH_OR_NAME] [--wineserver PATH_OR_NAME] [--toolchain-root DIRECTORY] [--compiler-transport PATH] [--resource-transport PATH] [--initialization-timeout SECONDS] [--compile-timeout SECONDS] [--link-timeout SECONDS] [--cleanup-timeout SECONDS] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

| Argument | Default | Description |
|---|---|---|
| `--jobs` `COUNT` |  | maximum parallel build workers (default: the CPUs this process may use, at most 8) |
| `--cold` |  | build from scratch without using the incremental cache |
| `--keep-workspace` `{never,on-failure,always}` | `on-failure` | keep the private workspace: never, only on failure, or always (default: on-failure) |

Shared: see [advanced execution options](#advanced-execution-options).

### `rbit verify`

Build every target from scratch and check exact bytes and trust evidence.

```
rbit verify [-h] [--jobs COUNT] [--keep-workspace {never,on-failure,always}] [--backend {auto,posix_wine_v1,windows_native_v1}] [--wine PATH_OR_NAME] [--wineserver PATH_OR_NAME] [--toolchain-root DIRECTORY] [--compiler-transport PATH] [--resource-transport PATH] [--initialization-timeout SECONDS] [--compile-timeout SECONDS] [--link-timeout SECONDS] [--cleanup-timeout SECONDS] [--policy {clean,allow-quarantine}] [--report-dir PROJECT_RELATIVE_DIRECTORY] [--action-receipt PATH] [--action-nonce LOWERCASE_SHA256] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

| Argument | Default | Description |
|---|---|---|
| `--jobs` `COUNT` |  | maximum parallel build workers (default: the CPUs this process may use, at most 8) |
| `--keep-workspace` `{never,on-failure,always}` | `on-failure` | keep the private workspace: never, only on failure, or always (default: on-failure) |
| `--policy` `{clean,allow-quarantine}` |  | optionally narrow the project's committed authenticity policy |
| `--report-dir` `PROJECT_RELATIVE_DIRECTORY` |  | write report.json and report.html beneath this project directory |
| `--action-receipt` `PATH` |  | publish a nonce-bound completion receipt after both reports finalize |
| `--action-nonce` `LOWERCASE_SHA256` |  | 64-hex invocation nonce paired with --action-receipt |

Shared: see [advanced execution options](#advanced-execution-options).

### `rbit discover init`

Create a small automatic search plan without compiling.

```
rbit discover init [-h] --source SOURCE --reference OBJECT_PATH --symbol SYMBOL [--translation-unit TRANSLATION_UNIT] [--plan PROJECT_RELATIVE_PATH] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

| Argument | Default | Description |
|---|---|---|
| `--source` `SOURCE` | required | project-relative source file to explore |
| `--reference` `OBJECT_PATH` | required | project-relative .obj file containing the reference function |
| `--symbol` `SYMBOL` | required | decorated function symbol |
| `--translation-unit` `TRANSLATION_UNIT` |  | select one build of the source only when it is compiled more than once |
| `--plan` `PROJECT_RELATIVE_PATH` | `reprobit/discovery.json` | new plan path (default: reprobit/discovery.json) |

### `rbit discover run`

Run a bounded request file (advanced).

```
rbit discover run [-h] [--report-json PATH] [--report-html PATH] [--state-directory DIRECTORY] [--jobs COUNT] [--wine PATH_OR_NAME] [--wineserver PATH_OR_NAME] [--toolchain-root DIRECTORY] [--compile-timeout SECONDS] [--cleanup-timeout SECONDS] request
```

| Argument | Default | Description |
|---|---|---|
| `request` |  | request JSON to run |

| Argument | Default | Description |
|---|---|---|
| `--report-json` `PATH` |  | canonical JSON report beside the request (default: REQUEST_STEM.report.json) |
| `--report-html` `PATH` |  | human review report beside the JSON report (default: REQUEST_STEM.report.html) |
| `--state-directory` `DIRECTORY` | `.reprobit-discovery` | incremental cache and runtime state beside the request |
| `--jobs` `COUNT` |  | maximum compiler workers (Wine is safely capped at 4; default: the CPUs this process may use, at most 8) |
| `--wine` `PATH_OR_NAME` | `wine` | POSIX Wine executable (default: wine from PATH) |
| `--wineserver` `PATH_OR_NAME` | `wineserver` | POSIX wineserver executable (default: wineserver from PATH) |
| `--toolchain-root` `DIRECTORY` |  | compiler installation override (normally remembered by rbit setup) |
| `--compile-timeout` `SECONDS` | `120.0` | limit for each compiler or resource-compiler step (default: 120) |
| `--cleanup-timeout` `SECONDS` | `10.0` | limit for stopping each isolated execution lane and its wineserver (default: 10) |

### `rbit discover clean`

Preview or remove one advanced discovery campaign's reusable state.

```
rbit discover clean [-h] [--state-directory DIRECTORY] [--preview] [--all-requests] request
```

| Argument | Default | Description |
|---|---|---|
| `request` |  | request JSON whose state should be removed |

| Argument | Default | Description |
|---|---|---|
| `--state-directory` `DIRECTORY` | `.reprobit-discovery` | campaign state beside the request (default: .reprobit-discovery) |
| `--preview` |  | show what would be removed without changing anything |
| `--all-requests` |  | remove state shared by every request named in its ownership marker |

### `rbit discover grind`

Use this for a project's initial mismatch. Search a bounded, project-wide set of low-cost adjustments using project-owned reference .obj files. The default is a preview. Saved local progress does not prove the complete project; only a fresh byte-exact result does. For a later regression in an already-exact project, use rbit repair instead.

```
rbit discover grind [-h] [--accept-exact | --accept-progress] [--reference-object TU=PROJECT_PATH] [--max-symbols COUNT] [--expert-plan PROJECT_RELATIVE_PATH] [--jobs COUNT] [--backend {auto,posix_wine_v1,windows_native_v1}] [--wine PATH_OR_NAME] [--wineserver PATH_OR_NAME] [--toolchain-root DIRECTORY] [--compiler-transport PATH] [--resource-transport PATH] [--initialization-timeout SECONDS] [--compile-timeout SECONDS] [--link-timeout SECONDS] [--cleanup-timeout SECONDS] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | ReproBit project to search (default: .) |

| Argument | Default | Description |
|---|---|---|
| `--accept-exact` |  | save only if a fresh run reproduces the complete project exactly |
| `--accept-progress` |  | save bounded, locally proven function adjustments even while the complete project still differs |
| `--reference-object` `TU=PROJECT_PATH` |  | pair a translation unit with a reference .obj; repeat for additional units |
| `--max-symbols` `COUNT` | `8` | maximum project functions to try in deterministic order (default: 8; max: 64) |
| `--expert-plan` `PROJECT_RELATIVE_PATH` |  | run one deliberately authored per-symbol plan instead of project-wide discovery |
| `--jobs` `COUNT` |  | maximum parallel build workers (default: the CPUs this process may use, at most 8) |

Shared: see [advanced execution options](#advanced-execution-options).

### `rbit state status`

Show retained runs, cache, reports, active leases, and disk usage.

```
rbit state status [-h] [project]
```

| Argument | Default | Description |
|---|---|---|
| `project` | `.` | project directory (default: .) |

### `rbit report`

Validate JSON and render self-contained HTML.

```
rbit report [-h] [--html PATH] input
```

| Argument | Default | Description |
|---|---|---|
| `input` |  | canonical report.json to validate and render |

| Argument | Default | Description |
|---|---|---|
| `--html` `PATH` |  | HTML output path (default: replace the input suffix with .html) |

### `rbit cmake-module`

Print the packaged CMake module path.

```
rbit cmake-module [-h] [--file]
```

| Argument | Default | Description |
|---|---|---|
| `--file` |  | print the packaged ReproBit.cmake file instead of its directory |

## advanced execution options

Defaults are suitable for people; these controls are mainly for CI and unusual hosts.

Accepted by `rbit repair`, `rbit build`, `rbit verify`, `rbit discover grind`. Flags a command's handler does not use are
omitted from that command (for example `--cold` outside `build`).

| Argument | Default | Description |
|---|---|---|
| `--backend` `{auto,posix_wine_v1,windows_native_v1}` | `auto` | execution backend (default: select from the host platform) |
| `--wine` `PATH_OR_NAME` | `wine` | POSIX Wine executable (default: wine from PATH) |
| `--wineserver` `PATH_OR_NAME` | `wineserver` | POSIX wineserver executable (default: wineserver from PATH) |
| `--toolchain-root` `DIRECTORY` |  | compiler installation override (normally remembered by rbit setup) |
| `--compiler-transport` `PATH` |  | POSIX transport selector for the locked compiler (paired with --resource-transport) |
| `--resource-transport` `PATH` |  | POSIX transport selector for the locked resource compiler |
| `--initialization-timeout` `SECONDS` | `600.0` | limit for each isolated execution-lane initialization (default: 600) |
| `--compile-timeout` `SECONDS` | `600.0` | limit for each compiler or resource-compiler step (default: 600) |
| `--link-timeout` `SECONDS` | `900.0` | limit for each librarian or linker producer (default: 900) |
| `--cleanup-timeout` `SECONDS` | `10.0` | limit for stopping each isolated execution lane and its wineserver (default: 10) |
