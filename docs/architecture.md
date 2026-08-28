# Architecture

ReproBit separates project intent, compiler execution, interventions, proof,
and oracle verification. A project describes targets and interventions as
data. A committed producer graph records every direct compiler, resource,
librarian, and linker invocation, while execution backends provide bounded
processes and stable compiler-visible paths. CMake can bootstrap that graph
during migration, but it is outside the certification runtime.

The producer and verifier are separate trust domains. A normal producer receives project
source and declared toolchain inputs, but no reference-image path or raw-byte service. It
publishes artifacts and provenance receipts. The verifier owns the reference image and reports
comparison results.

Primary source provenance distinguishes checked-in manifest bytes from reviewed project-overlay
bytes. When a project has a `source_overlay_graph`, its closed validator derives one declaration
counterfactual from immutable clean inputs. Typed declaration leaves need no compiler audit;
strict source leaves select their exact compiler owners, and strict headers conservatively select
all ordinary compilers because reader exposure is not independently sealed. Counterfactual audit
objects are excluded from terminal ancestry; the exact effective render is admitted with
`certified-project-overlay` only after the sparse evidence passes. The similarly named
`donor_source_overlay` family remains confined to private donor compilation and cannot supply a
primary project source.

## Layers

- The model and schema layers define stable identities, artifacts, interventions, costs, and
  verdicts.
- Source and binary-format layers provide deterministic parsing and rendering primitives.
- Recipe providers turn declared compiler output into a new artifact and issue a versioned
  certificate for narrowly defined invariants.
- The toolchain lock and producer graph describe commands without shell-string
  reparsing and bind them to exact source, toolchain, path, and target authority.
- Backends construct logical path arenas, isolate mutable compiler state, and own every child
  process.
- The engine schedules the artifact DAG and the report layer renders its receipts.

The proof report carries the complete canonical build-execution receipt and literal target-
comparison receipts as a public runtime-binding preimage. Its digest is repeated at the report
boundary and cross-checked against the cold-build verdict, target digests, sizes, paths, and
comparison result. A consumer can therefore recompute the binding without access to process
memory or an implementation-specific run identifier.

Classic runtime evidence follows producer causality in the same direction as the build: sealed
source and toolchain inputs feed compiler object/PDB pairs and resource outputs; those products
feed librarian archives; archives, remaining objects, and resources feed the linker image; only
declared terminal transforms may follow the image. Current-run producer outputs carry both a
content-addressed artifact and a producer receipt naming the locked tool and execution step.
Reports reject missing references, digest or size disagreement, cycles, and stage-reversing edges
such as an object derived from a linked image.

Schema v3 currently recognizes only the reviewed built-in classic-MSVC adapter
and closed recipe registry. Adding another certification adapter requires a
ReproBit code and schema release; project files and arbitrary installed packages
cannot inject executable providers, scripts, or Python callables.
