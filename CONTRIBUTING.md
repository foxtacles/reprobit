# Contributing to ReproBit

ReproBit is a library whose outputs are trust claims. Every change must keep
the gates below green, and no change may weaken a test, validator, schema, or
authenticity check to get there.

## Set up a development environment

```console
git clone https://github.com/isledecomp/reprobit.git
cd reprobit
python -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -e '.[test]'
```

Python 3.11 or newer is required. The runtime dependencies are `pydantic` and
`rich` (see `pyproject.toml`).

## Quality gates

Run all four before every commit; CI (`.github/workflows`) runs the same
commands plus `python -m build` and `python -m pip check`:

```console
ruff check && ruff format --check && mypy && python -m pytest -q
```

- `ruff check` / `ruff format --check`: lint and formatting (line length 100,
  configuration in `pyproject.toml`).
- `mypy`: strict typing of `src/reprobit` and the CI helpers in `scripts/`.
- `python -m pytest -q`: the full suite from `tests/` (`testpaths` in `pyproject.toml`;
  `-ra --strict-config --strict-markers` are always on).

Several generated files are checked into the repository and each has a test
that fails when it is stale:

| Committed file(s) | Regenerate with | Guarding test |
|---|---|---|
| `docs/classic-recipe-reference.md` | `python -m reprobit.recipe_reference` (or `--check`) | `tests/test_intervention_metadata.py::test_committed_recipe_reference_is_current` |
| `docs/cli-reference.md` | `python -m reprobit.cli_reference` | `tests/test_cli_reference.py` |
| `schemas/*.schema.json` | the generator named per file in the test (`project_document_schemas()`, `msvc_discovery_request_json_schema()`, `discovery_report_json_schema()`, `report_json_schema()`, written as `canonical_json`) | `tests/test_package.py::test_committed_json_schemas_are_current` |

## Test layout

- `tests/test_*.py`: test modules named for the module family they cover (`test_classic_*`,
  `test_cli_*`, `test_discovery_*`, `test_msvc*`, `test_repair*`, ...).
- `tests/fixtures/`: small committed inputs such as `classic_smoke.cpp`.
- Real-compiler tests skip themselves unless a toolchain root is configured in
  the environment: `REPROBIT_MSVC_4_2_ROOT` (and `REPROBIT_MSVC_5_0_*_ROOT`
  for the modeled 5.0 profiles). Some additionally need Wine on POSIX, native
  Windows, or the `REPROBIT_MSVC42_PE_*`/`REPROBIT_MSVC42_PDB_*` fixture
  variables. A default run therefore reports a few dozen skips; that is
  expected.
- Windows-only behaviour (directory junctions, logon sessions, Job Objects)
  is skipped on other platforms and exercised by the Windows CI job.
- Structural tests that protect the design rather than a feature:
  `tests/test_architecture.py` (the internal import graph must stay acyclic,
  `reprobit/classic/__init__.py` stays documentation-only, production code
  imports internal owners directly, and nothing under `reprobit/classic/`
  reaches the `classic_*` runtime layer or anything built on it, even
  transitively), `tests/test_project_identity_leakage.py`
  (no downstream project name may appear anywhere under `src/`, `tests/`,
  `docs/`, or `schemas/`; the root `README.md` and this file are outside that
  scan), and `tests/test_package.py` (wheel contents and schema currency).

When a test asserts exact CLI wording and you change that wording on purpose,
update the assertion to the new text. Do not delete assertions, loosen
matchers, or add skips to make a test pass.

A project-schema bump must include concise upgrade notes and one tested,
version-specific conversion or regeneration path from the immediately
preceding schema. Keep that path explicit; do not add a generic migration
framework that guesses how to handle unknown versions.

## Module map

`src/reprobit/` is one flat package plus the `classic/` subpackage. Families
by filename prefix:

| Family | Modules | Role |
|---|---|---|
| Core model | `model`, `schema`, `intervention_metadata`, `costs`, `strict_json`, `formats` | Artifacts, verdicts, provenance, the schema-v3 record types, the cost model, canonical JSON. |
| Project records | `project_loader`, `project_readiness`, `source_*`, `authority_snapshot`, `onboarding`, `user_config`, `paths`, `secure_paths*` | Loading and cross-validating `reprobit.toml` and `reprobit/`, the readiness checklist, source manifest locking, safe path handling. |
| Execution | `project_execution`, `engine`, `execution`, `scheduler`, `dag_queue`, `process`, `backends`, `native_device_map`, `sealed_namespace`, `state*`, `transactions`, `cache`, `incremental*`, `artifacts`, `assets`, `context`, `progress` | Running the producer graph in bounded child processes with logical paths, the content-addressed cache, warm builds, state directories. `project_execution` owns build/verify inputs and operations shared by CLI and repair. |
| Toolchains | `toolchains`, `msvc_*`, `msvc42_*` | Profiles, authentication, locking, and the MSVC compile/link drivers. |
| Verification | `verify`, `evidence_audit`, `oracle_pe32`, `binary`, `coff_format`, `ia32_decode`, `small_msf` | Sealing and comparing references, origin audits, PE/COFF/PDB parsing. |
| Classic algorithms | `classic/` | The MSVC recipe families' pure algorithms: COFF and CodeView projection, candidate composers, rewriting and scheduling certificates, semantic contracts, source overlays. A leaf: it imports only the model, format, path and toolchain-profile foundations, never a `classic_*` module. `classic` is the label for that older MSVC family (see [docs/architecture.md](docs/architecture.md)). |
| Classic runtime | `classic_*` | Everything that runs the package against a project: donor rendering (`classic_donors`), family dispatch (`classic_project`), execution (`classic_runtime_*`, `classic_orchestration`), warm builds (`classic_incremental_*`), quarantine handling, and the repair and retune steps (`classic_repair_*`, `classic_measured_pin_repair`, `classic_redundant_action_repair`, `classic_donor_retune_*`, `classic_source_regeneration`). |
| Discovery | `discovery_*`, `declaration_shapes` | `rbit discover grind` and `rbit discover run`, the bounded declaration generators, their reports. |
| CMake import | `cmake_*`, `producer_graph`, `producer_graph_cmake` | Import and source-list refresh for the committed producer graph. |
| Repair | `repair*` | `rbit repair`: analysing an edit, re-issuing guidance, publishing. |
| Reports | `report*`, `action_summary` | The JSON report model and the HTML renderer, GitHub Action summary. |
| CLI | `cli*` | argparse tree (`cli._parser`), `CLIOutput` text/NDJSON events, one `cli_<area>` module per command group, `cli_reference` (docs generator). |

## Adding a classic recipe family

Families are a closed set; a new one is a library release, not a project
edit. The pieces that must change together are:

1. Add an enum member and one `CLASSIC_RECIPE_METADATA` entry in
   `reprobit.intervention_metadata` with its role, cost class, and execution
   coverage. Role sets, cost mapping, and display labels derive from this
   registry. Regenerate the schemas and run `python -m reprobit.recipe_reference`.
2. Implement the explicit renderer or composer branch in `classic_donors` or
   `classic_project`, and register and prove its contract in
   `classic.semantic_contracts`. Metadata contains no callable or proof
   authority; a catalog entry alone cannot implement a recipe. The validator
   implementation digest distinguishes certificates after semantic changes.
3. Add renderer/composer, semantic-contract, and cost tests. Update the
   handwritten behavior and proof descriptions in
   [docs/interventions.md](docs/interventions.md); the generated
   [family catalog](docs/classic-recipe-reference.md) records shared metadata.

## Regression gate for behaviour changes

Two tiers protect byte identity:

1. The unit and integration suite above, including the real-compiler tests
   when a toolchain root is configured.
2. A cold `rbit verify` of the LEGO Island reference project (see the
   README section on that case), run with the real MSVC 4.2 toolchain. It
   must end with all targets byte-identical and match the reference project's
   reviewed quarantine boundary. The expected exception count, byte count,
   range count, and digest live in the reference project's
   [verification workflow](https://github.com/isledecomp/isle/blob/master/.github/workflows/reprobit.yml),
   alongside the publication gate that enforces them. Compare the report with
   that checkout's expected values; do not copy a second baseline into this
   guide. Any unexpected difference is a regression even when the build is
   byte-exact. A deliberate reduction requires reviewing and updating the
   reference project's expected boundary; an increase is a blocker.

`rbit verify` is always cold. Warm `rbit build` results are useful while
iterating but never stand in for the verify tier.

Measure incremental performance on a disposable checkout of the reference
project with the same compiler, host, worker count, and source revision:

```console
python scripts/benchmark_build.py /path/to/reference-checkout --jobs 8 --runs 3
```

The script runs one cache-priming build, then measures fresh-process builds.
Every measured build must reuse all work, start no compiler environment, and
leave target and comparison outputs unchanged. It reports wall-clock times,
including CLI startup, as JSON. Use `--max-warm-seconds` to gate the median on
a controlled benchmark machine; ordinary tests impose no machine-specific
timing threshold. This benchmark writes normal build state and outputs.

## Releasing

There are no scheduled releases; a release is a tag.

1. On `master`, set `version` in `pyproject.toml` and
   `reprobit.__version__` and the CLI's source-checkout fallback to the release
   number (they must agree; `tests/test_package.py` checks that) and land that
   commit through CI.
2. Tag it `X.Y.Z` and push the tag (`vX.Y.Z` is also accepted). Keep release tags
   fixed at their verified commits. The CI workflow runs every job on the
   tag and, when all of them pass, the `release` job checks that the tag
   names the packaged version (`scripts/check_release_tag.py`), builds the
   sdist and wheel, re-runs the wheel check, and creates a GitHub release
   with both files attached and generated notes. Nothing is published to
   PyPI.
3. Downstream projects that build with the composite Action should check
   out ReproBit at that tag (or its commit) rather than at `master`, so a
   ReproBit regression cannot break their verification without a deliberate
   update. A second, non-blocking job that tracks `master` is the place to
   see such regressions early. That pin lives in the downstream workflow,
   not here.

## Commits and pull requests

- Keep commits small and self-contained; subject line of at most 72
  characters and a body that explains what changed and why.
- Documentation must be accurate: derive every claim from code or an existing
  document, and reproduce CLI output rather than paraphrasing it.
- Do not add dependencies without discussion; the runtime dependency list is
  deliberately short.
- Never commit reference binaries, compiler installations, or generated
  state (`.reprobit-state/`, `.reprobit-transactions/`).
