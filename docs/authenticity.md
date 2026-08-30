# Authenticity model

Byte equality is necessary but does not prove how an artifact was produced. ReproBit therefore
reports independent claims:

- `byte_exact` means a produced image is literally equal to its reference oracle.
- `logic_certified` means every non-native intervention satisfied its registered proof
  obligations.
- `toolchain_origin` means first-party code and data descend only from declared compiler,
  resource-compiler, librarian, or linker artifacts. Certified metadata changes are reported
  separately.
- `clean` additionally requires a cold build and no quarantined action.

Every artifact has a provenance node. A node names its inputs, transformation kind, certificate,
and output digest. Stale or unreceipted artifacts are refused. Object files and compiler PDBs are
treated as one provenance unit because retained PDB state can change emitted type indices.

## Noncertifying debug companions

The certified executable or library is never normalized. When a project also asks for symbols,
ReproBit creates a separate private executable/PDB pair for comparison tools. For MSVC 4.2 it
recouples that private executable's PE timestamp and NB10 identity to the already-certified image,
then canonicalizes only parsed PDB 2.00 SmallMSF bookkeeping: process-local pointers, ABI padding,
free pages, the PDB signature, and bytes beyond a length-delimited 255-byte procedure name. Types,
symbols, addresses, paths, source lines, FPO data, relocations, and section layout are preserved.

The parser admits only the exact old structures it understands. Unknown versions, malformed or
aliased streams, unexplained record tails, or a mismatched executable/PDB identity fail before any
output is published. A second parse proves idempotence. The report records raw and published
hashes, every permitted category, a bounded changed-range summary, and a projection hash proving
that all bytes outside the complete policy ranges were identical. These files remain explicitly
noncertifying and cannot enter the release artifact graph. See Microsoft's
[PE debug-directory format][pe-format] and LLVM's [PDB/MSF format overview][pdb-format] for the
surrounding container structures; ReproBit's SmallMSF parser further restricts that grammar to the
1 KiB-page MSPDB41 variant.

[pe-format]: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
[pdb-format]: https://llvm.org/docs/PDB/index.html

Semantic certificates are consumable proof objects rather than opaque proof hashes. Each carries
its canonical input and output statements, the digests of those statements, and explicit artifact
claims that identify the statement relation, artifact id, digest, and size. The report validator
requires each claimed receipt to occur in the corresponding statement and to match the referenced
artifact exactly. Candidate and donor proofs attach to the actual object artifact; archive and link
edges then establish that object's ancestry into a terminal image. Project-overlay proofs bind
their sparse per-object audit receipts without pretending to be a proof about the already-linked
image.

## Classic semantic obligations

A fresh execution receipt proves only that a declared transformation ran and produced the
recorded bytes. It does not prove that the transformation preserved program behavior. Every
classic recipe therefore requires a family-specific runtime obligation named
`semantic_equivalence.<family>`, bound to the affected artifact and transform provenance. A
generic `fresh_execution` obligation, or a committed expected-observation pin, cannot make a
classic intervention `logic_certified`.

The source-overlay renderer proves deterministic syntax rendering, clean-input pins, anchor
resolution, removed-range pins, and effective-output identity. None of its operation families is
semantic-inert merely because rendering succeeded:

- Insert and append operations can affect lookup, macros, the ODR, initialization, emitted code,
  and line-sensitive constructs even for declaration-like generators such as `fwd`, `lines`, or
  `extern_run`.
- Replace and delete operations can directly change behavior. Relocating the same source bytes
  can still change scope, ordering, lifetime, or control flow.
- Local/data generators such as `dead_updates`, `fixed_array_fill`, `inclusive_extent`,
  `ctor_alloc_lift`, `capture_tail`, `assert_reseat`, and `literal_alias` require their own typed
  side-condition proofs; their closed syntax is not an equivalence proof.
- Generated translation-unit placement and link admission alter the producer graph and need graph-
  and linker-specific obligations.

The built-in source-overlay validator therefore issues a typed proof only when current-run
evidence establishes all of its closed obligations. For a project-level `source_overlay_graph`,
it derives a declaration counterfactual from the exact manifest-clean tree. Closed declaration
leaves remain present in that counterfactual and require no extra compile; strict semantic-delta
leaves select the exact compiler owners of their source for counterfactual/effective object
congruence. A strict header conservatively selects every ordinary compiler node because reader
exposure is not separately sealed. Counterfactual objects are evidence only and cannot enter
terminal ancestry. Only after the validator binds source theorems, sparse compiler receipts,
every effective invocation namespace, run and graph identities, and operation-specific evidence
may an effective overlay receipt carry the primary origin `certified-project-overlay`; only
effective primary products occupy the committed terminal graph seats.

This project-overlay path is categorically separate from the classic `donor_source_overlay`
family. A donor overlay remains `donor_private_rendering_only`: its rendered source can enter only
a private donor compile, and the resulting object can reach a candidate only through a registered
binary-family semantic proof. It can never claim `certified-project-overlay` or occupy a primary
project compiler seat. Declared generated carriers remain isolated separately, and closed COFF
reachability must show that they add no reachable definitions, startup hooks, exports, unsafe
linker directives, divergent COMDATs, or novel external dependencies. Unknown COFF constructs,
incomplete link closures, missing family validators, unpaired epochs, and stale proof bindings fail
closed. The validator identity, implementation digest, exact input statement, and output trace are
bound into the semantic proof.

Reference images are comparison oracles, not payload sources. Raw oracle access is withheld from
normal producers. A separately bound reference-byte capability can be enabled only by an exact,
non-growing allowlist; its presence always prevents a clean verdict.

Candidate composers receive fresh seed/donor artifacts, closed recipe parameters, and digest
expectations. They do not receive a retail function body. Candidate-only receipts cannot claim
byte equality; the sealed literal verifier issues that observation after production. The verifier
also refuses candidate/oracle hardlink aliases and detects replacement of either file during a
comparison.

`allow-quarantine` is not a general relaxed mode. It still requires a cold build, literal byte
identity, passing logic certificates, and complete non-quarantined origin integrity. It permits
only the finite ranges named by the exact reference-byte exception allowlist and leaves
`toolchain_origin` false.

ReproBit protects against accidental or undeclared transformations, stale artifacts, path drift,
concurrent mutation, and oracle-payload leakage. It does not claim to defend against a hostile
operating-system administrator or a deliberately modified ReproBit implementation; run receipts
therefore record the exact package and adapter identities.

## Trust boundary

Trusted code consists of the reviewed ReproBit implementation, its closed adapter/recipe
registry, the admitted toolchain lock, and the host execution primitives that enforce isolation.
Project manifests are untrusted data. Reference images are trusted only as sealed comparison
inputs; they are not assumed to explain program behavior.

The model protects against stale artifacts, accidental path drift, malformed or overly broad
recipes, hidden project scripts, producer/oracle aliasing, partial process cleanup, and incomplete
provenance. It is not a sandbox against a hostile kernel, administrator, debugger attached to a
trusted process, or a deliberately modified ReproBit installation. For consequential releases,
pin the ReproBit source revision, review the toolchain lock, and reproduce on an independently
administered runner.
