# Project format

Most people do not need to edit these files by hand. `rbit init`, `rbit source
lock`, `rbit import cmake`, and accepted discovery results create or update
them; review and commit the resulting changes like ordinary project files.

A project has a small `reprobit.toml` entry point and strict JSON files under
`reprobit/`. After `rbit source lock`, `reprobit/source-manifest.json` lists the
complete source read set and the hash of every file. Inspect a proposed refresh
with `rbit source preview`, then publish it with `rbit source lock`. The update
rechecks every listed file and refuses to overwrite records when a source change
requires other saved records to be repaired. For normal edits to already-listed
files, use `rbit repair .`; reserve preview and lock for added or removed files.
Re-import CMake only when that source-list change also changes which files a
CMake target compiles. Committed files use
project-relative source, output, and reference-binary paths plus stable DOS
paths seen by the compiler. The CLI project root selects the physical checkout;
`--toolchain-root` supplies the local compiler installation. There is no
separate reference-binary root override.

Interventions are identified by stable IDs and a versioned `kind`. Each record declares its
scope, parameters, dependencies, rationale, and beneficiaries. Proof files contain committed
expectations and digest-only redactions used to check newly issued evidence. They are never
treated as current-run provenance or certificates.

Unknown keys, duplicate JSON keys or IDs, dangling references, cycles, stale proof inputs, and
arbitrary payload fields are errors. File ordering never has semantic meaning; shards are loaded
in stable ID order and committed to one canonical model digest.

The entry point selects one locked toolchain profile, an exact DOS logical-path profile, a build
adapter, an authenticity policy, and target artifact/reference-binary pairs. The schema calls the
reference path an `oracle`. Reviewed direct builds use
`build.kind = "producer-graph"`; the remaining `command` variant is a non-certifying developer
convenience and is rejected by `verify`. CMake supplies graph-extraction input through the normal
`rbit import cmake` flow. The split `rbit graph configure` and `rbit graph extract` commands are
advanced alternatives; CMake is not a project build-adapter kind. The current schema-v3
certification path is the built-in MSVC adapter. Physical host paths must not be embedded
in JSON files.
`reprobit/build-plan.json` is declarative authority for translation units,
source-overlay IDs, explicit COMDAT group-order transforms, analysis-only link options, pinned
project SDK libraries, archive exceptions, and target gates; it cannot name Python callables or
shell fragments. `reprobit/producer-graph.json` separately records the complete direct compiler,
resource-compiler, librarian, and linker DAG. Schema v3 binds it to the toolchain lock,
logical-path profile, target set, exact terminal artifact paths, and every explicit direct source
edge. Unrelated files may enter or leave the source manifest without changing commands; recursive
include reads remain closed and sealed by the runtime source namespace.
The toolchain lock keeps content and profile configuration deliberately separate: file/tree receipts
are exact installed-byte authority, while each `profile_sources` entry freezes a reviewed immutable
repository input associated with the selected profile's installed paths. This mapping is not origin
evidence and does not prove that arbitrary locally locked bytes were downloaded from that revision.
Profile-source paths cannot overlap, name content absent from the lock, or claim a locked wrapper
outside the profile mapping. The authenticated provisioner supplies acquisition proof for its
embedded MSVC 4.2 authority.
The source manifest and build plan independently bind current source contents, so an edit at an
existing admitted path does not force a CMake re-extraction.

Object and resource inputs to librarian/linker nodes require current-run build ancestry. A raw
source archive is never an ordinary `source/` edge: each permitted third-party exception has a
typed `quarantine-archive/` edge, an exact source-manifest digest pin, and a finite build-plan link
contract. Cross-validation checks the terminal target, ordered adjacent library identities, and
occurrence count, so an authorized archive cannot silently appear in another target or at an
additional link site. Noncompiler argv uses a closed role grammar; unknown or unmodeled switches
are rejected rather than guessed to be harmless.

Bare `system-library/` identities normally resolve only through locked toolchain library roots.
If an earlier project `LIBPATH` selects an external SDK archive, that path and SHA-256 must also
appear in `project_sdk_libraries` and match the source manifest. A source-root
library that lacks that independent pin is rejected even when its basename was declared as a
system library.

The source manifest pins the clean baseline. Translation-unit `source_digest` fields pin reviewed
effective bytes. A project-role `source_overlay_graph` may account for the difference, but the
project never declares its own source origin: the closed runtime validator assigns
`certified-project-overlay` only after its typed source theorem, any required sparse declaration-
counterfactual compiler audits, and every effective compiler invocation succeed. A donor-role
`donor_source_overlay` is different authority; it remains private to a donor lane and cannot
occupy a primary compiler seat.

Schema v3 is strict and intentionally not forward-tolerant. Unknown fields require a schema and
library update so a misspelling can never weaken a proof obligation. Every generated schema is a
self-contained Draft 2020-12 root with a stable `urn:reprobit:schema:...` identity:

- `project-v3.schema.json` validates the `reprobit.toml` model.
- `toolchain-lock-v3.schema.json`, `source-manifest-v3.schema.json`, and
  `build-plan-v3.schema.json` validate their corresponding committed documents.
- `producer-graph-v3.schema.json` validates direct producer authority. Every
  graph source input must be in the source manifest or a reviewed source-overlay
  output; unrelated manifest entries do not force command-graph extraction.
- `intervention-document-v3.schema.json`, `proof-document-v3.schema.json`, and
  `oracle-document-v3.schema.json` validate individual files.
- `catalog-v3.schema.json` is the synthetic aggregate for tooling that needs every definition.
- `report-v2.schema.json` validates canonical run reports. Version 2 makes the
  public `run_id` recomputable over the full report and discloses every locked
  portable toolchain-tree receipt; version 1 reports are intentionally rejected.

These roots support editors and standalone validators. Regard `rbit validate` as authoritative
because it additionally checks cross-document relationships and current admitted/effective source
bytes.
