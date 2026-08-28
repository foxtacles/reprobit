# Project format

A project has a small `reprobit.toml` entry point and strict JSON shards under `reprobit/`.
`reprobit/source-manifest.json` is a complete, portable digest inventory of the admitted source
read set. Inspect a proposed refresh with `rbit source preview`, then publish it with `rbit source
lock`. The lock transaction rechecks every admitted file and updates only safe manifest
bindings; it refuses stale effective-TU or source-overlay authority instead of silently updating
reviewed intervention/proof pins. Committed files use project-relative source, artifact, and
oracle paths plus logical DOS seats. The CLI project root selects the physical checkout;
`--toolchain-root` supplies the local compiler installation. There is no separate oracle-root
override.

Interventions are identified by stable IDs and a versioned `kind`. Each record declares its
scope, parameters, dependencies, rationale, and beneficiaries. Proof shards contain committed
expectations and digest-only redactions used to check newly issued evidence. They are never
treated as current-run provenance or certificates.

Unknown keys, duplicate JSON keys or IDs, dangling references, cycles, stale proof inputs, and
arbitrary payload fields are errors. File ordering never has semantic meaning; shards are loaded
in stable ID order and committed to one canonical model digest.

The entry point selects one locked toolchain profile, an exact DOS logical-path profile, a build
adapter, an authenticity policy, and target artifact/oracle pairs. Reviewed direct builds use
`build.kind = "producer-graph"`; the remaining `command` variant is a non-certifying developer
convenience and is rejected by `verify`. CMake is a graph-extraction input selected by
`rbit graph configure`, not a project build-adapter kind. The current schema-v3 certification path
is the built-in classic-MSVC adapter. Physical host paths must not be embedded in JSON shards.
`reprobit/build-plan.json` is declarative authority for translation units,
source-overlay IDs, terminal producers, and target gates; it cannot name Python callables or shell
fragments. `reprobit/producer-graph.json` separately records the complete direct compiler,
resource-compiler, librarian, and linker DAG. Schema v2 binds it to the canonical source path
topology, toolchain lock, logical-path profile, target set, and exact terminal artifact paths.
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
appear in the build plan's typed SDK-authority view and match the source manifest. A source-root
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
- `producer-graph-v2.schema.json` validates direct producer authority. It can
  read conservative v1 graphs, while v2 separates the stable source path
  topology from independently locked source contents so ordinary edits do not
  force command-graph extraction.
- `intervention-document-v3.schema.json`, `proof-document-v3.schema.json`, and
  `oracle-document-v3.schema.json` validate individual shards.
- `catalog-v3.schema.json` is the synthetic aggregate for tooling that needs every definition.
- `report-v2.schema.json` validates canonical run reports. Version 2 makes the
  public `run_id` recomputable over the full report and discloses every locked
  portable toolchain-tree receipt; version 1 reports are intentionally rejected.

These roots support editors and standalone validators. Regard `rbit validate` as authoritative
because it additionally checks cross-document relationships and current admitted/effective source
bytes.
