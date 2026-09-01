# Glossary

Short definitions of the terms that appear in `rbit` output, project records,
and the other documents. Each entry ends with a pointer to the code or document
it is derived from; terms whose meaning cannot be traced to code or an existing
document are deliberately absent. Read [concepts.md](concepts.md) for the
narrative and [cli.md](cli.md) for the commands.

## Verdicts and claims

- **byte-exact** (`byte_exact`): the rebuilt terminal artifact is
  byte-for-byte identical to the committed reference. The verifier seals each
  reference binary before execution and compares against that sealed copy.
  (see [authenticity.md](authenticity.md), `reprobit.verify.seal_file_oracle`)
- **logic certified** (`logic_certified`): every intervention that touched the
  output carries a passing certificate, so the adjustments preserved the
  program's logic. (see [authenticity.md](authenticity.md))
- **toolchain origin** (`toolchain_origin`): the artifact's recorded ancestry
  leads only to the declared source and the locked toolchain, never to bytes
  copied from a reference image. (see [authenticity.md](authenticity.md))
- **clean**: the verdict when byte-exact, logic-certified, and toolchain-origin
  all hold and no quarantine is disclosed. `--policy clean` is the strict
  policy; `allow-quarantine` accepts a disclosed quarantine instead of failing.
  (see [authenticity.md](authenticity.md), `reprobit.model.AuthenticityPolicy`)
- **quarantine**: disclosed byte ancestry that prevents a clean verdict, listed
  as byte ranges of the final artifact. `rbit verify` prints the intervention
  count, byte total, and range count of every quarantine. (see
  `reprobit.model.Quarantine`, [cli.md](cli.md#reading-the-report))
- **cost**: the relative cost of every intervention a project needs, summed
  from a fixed table of cost classes. The number itself is informational; only
  the claims above pass or fail. (see [costs.md](costs.md))

## Sources of bytes

- **reference**: the project-owned original binary that a target must
  reproduce. References stay outside the repository and are never
  redistributed. (see [project-format.md](project-format.md))
- **oracle**: a reference image used only for comparison. Copying bytes out of
  an oracle into the build is an *oracle install*: the most expensive cost
  class, and always a quarantine. (see [authenticity.md](authenticity.md),
  [costs.md](costs.md))
- **candidate**: the artifact the clean rebuild produces before the verifier
  compares it with the reference. (see [concepts.md](concepts.md))
- **donor**: an object compiled privately, in a different declaration state
  from the clean source, whose function bytes replace one function of the
  candidate under a proof. A donor is charged once even when several functions
  benefit. (see [costs.md](costs.md), `reprobit.schema.ClassicRecipeRole`)
- **beneficiary**: a function that receives the effect of a shared intervention
  such as a donor; beneficiaries are recorded with the intervention so its cost
  is attributed once. (see [costs.md](costs.md),
  [project-format.md](project-format.md))
- **overlay**: reviewed source edits rendered onto the clean source before
  compiling. A `source_overlay_graph` is project-level authority; a
  `donor_source_overlay` is private to the donor rendering and never reaches
  the clean tree. (see `reprobit.schema.ClassicRecipeFamily`,
  [authenticity.md](authenticity.md))
- **counterfactual**: an evidence-only compile of the source without an
  overlay or declaration, used to audit what changed. Counterfactual objects
  are never linked into the candidate. (see [authenticity.md](authenticity.md))
- **companion**: a noncertifying debug executable and PDB pair that some
  comparison tools need. It is written under the sibling `reprobit-debug/`
  directory whenever an imported link asks for debug data, and it never
  contributes to a verdict. (see [authenticity.md](authenticity.md),
  [getting-started.md](getting-started.md#debug-companions-and-the-exported-source-view))
- **terminal artifact**: the final declared output of a target, the file that
  is compared with the reference; the last node of the producer graph.
  (see [project-format.md](project-format.md), `reprobit.model.Artifact`)
- **translation unit**: one compiler invocation on one source file. Records
  address translation units by a stable `tu.<hash>` identifier. (see
  [cli.md](cli.md#rbit-repair), `reprobit.schema`)

## Interventions and proofs

- **intervention**: a declared, reviewed adjustment to how the clean source is
  compiled or linked. Each is a JSON record with an identifier, versioned
  `kind`, scope, parameters, dependencies, rationale, beneficiaries, and cost.
  (see [project-format.md](project-format.md),
  [interventions.md](interventions.md))
- **kind**: the versioned discriminator of an intervention record, for example
  `classic_recipe` or `state_carrier`. New kinds are added as reviewed library
  releases, not by editing records. (see [project-format.md](project-format.md),
  `reprobit.schema`)
- **recipe**: a `classic_recipe` intervention: a closed, parameterised
  operation from a fixed family, described entirely as data. (see
  `reprobit.schema.ClassicRecipeIntervention`)
- **family**: one member of the closed `ClassicRecipeFamily` set, such as
  `declaration_shape` or `same_slot_resize`. Semantic proofs also name the
  family they certify. (see `reprobit.schema.ClassicRecipeFamily`,
  `reprobit.model.SemanticProof`)
- **carrier**: a `state_carrier` intervention, a declared source element whose
  purpose is to change the compiler's internal state before the function that
  matters. Proven non-emitting declarations cost 1 point; emitting carriers
  cost 5. (see `reprobit.schema.StateCarrierIntervention`,
  [costs.md](costs.md))
- **mosaic**: a function body assembled from instruction ranges of more than
  one compiled candidate of the same symbol. `rbit discover run` reports bounded
  same-symbol mosaic proposals as evidence only; accepted mosaics are binary
  surgery and priced as such. (see [discovery.md](discovery.md),
  [costs.md](costs.md))
- **proof**: evidence that an intervention preserved logic. Proof documents in
  `reprobit/proofs/` hold committed expectations; each run discharges proof
  obligations against them and records the outcome in a certificate. (see
  [project-format.md](project-format.md), `reprobit.model.ProofObligation`)
- **expectation**: a committed value in a proof document, possibly redacted to
  a digest, that newly issued evidence must match. (see
  [project-format.md](project-format.md))
- **certificate** (also *logic certificate*): the proof receipt for one
  intervention, listing its obligations; it passes only when every obligation
  passed. The `logic_certified` claim requires a passing certificate for every
  intervention that reached the output. (see `reprobit.model.Certificate`,
  [authenticity.md](authenticity.md))
- **provenance**: the ancestry DAG of an artifact. Each node has one of the
  kinds `source`, `toolchain`, `producer`, `object_transform`, `intervention`,
  `metadata_transform`, `external`, or `oracle_install`, so the toolchain-origin
  claim can be checked node by node. (see `reprobit.model.ProvenanceKind`,
  `reprobit.model.ProvenanceNode`)
- **content-addressed**: identified by the digest of its bytes. Build
  artifacts and the project-local cache are content-addressed, which is what
  lets a warm build reuse a step whose inputs are unchanged. (see
  `reprobit.model.Artifact`, [cli.md](cli.md#rbit-build))
- **COMDAT**: a COFF section that the linker may pick among duplicates.
  ReproBit records changes to COMDAT group order as `object_transform`
  provenance rather than hiding them. (see `reprobit.model.ProvenanceNode`)
- **reloc**: a base-relocation entry in the PE image. Relocation-layout
  handling appears in the `equal_body_eh_reloc_layout` family and in the
  50-point cost class. (see `reprobit.schema.ClassicRecipeFamily`,
  [costs.md](costs.md))

## Project records

- **record**: any committed JSON document under `reprobit/`: interventions,
  proofs, oracles, the source manifest, the build plan, and the producer graph.
  `rbit repair` calls the subset that steers a build *saved build guidance*.
  (see [project-format.md](project-format.md), [cli.md](cli.md#rbit-repair))
- **shard**: one small document in the `interventions/` or `proofs/` directory.
  Shards are loaded in stable identifier order so reviews stay per-file. (see
  [project-format.md](project-format.md))
- **authority**: the committed record that settles a question, such as which
  source bytes are admitted or which interventions exist. Run output never
  overrides authority; `rbit status` reports whether all saved project files
  agree. (see `reprobit.schema`, [cli.md](cli.md#rbit-status))
- **sealed**: pinned by digest before use, so later steps cannot change the
  bytes unnoticed. References are sealed before execution, and the grind seals
  its copy of the project authority before candidates compile. (see
  `reprobit.verify.seal_file_oracle`, `reprobit.discovery_grind`)
- **identity**: a digest that names one exact thing, such as the producer
  graph (`graph_digest`) or a validator implementation, so a record can be
  bound to it. Target and toolchain overrides are checked against the
  committed project identities. (see [cli.md](cli.md#rbit-verify),
  [authenticity.md](authenticity.md), `reprobit.classic_incremental_keys`)
- **directive**: a linker-only library edge discovered from `.drectve` sections
  of object files. `rbit import cmake --directive-input TARGET=LIBRARY` seeds
  one when the import cannot see it. (see [cmake.md](cmake.md))

## Execution

- **cold**: built from scratch with the cache bypassed. `rbit verify` is always
  cold; `rbit build --cold` forces it. Only a cold build certifies. (see
  [cli.md](cli.md#rbit-verify))
- **warm**: an incremental `rbit build` that reuses cached steps whose inputs
  are unchanged. Warm results are for iteration, never for certification. (see
  [cli.md](cli.md#rbit-build))
- **logical path**: the DOS-style path the compiler sees, such as `R:\source`,
  independent of where the checkout physically lives. Fixed at `rbit init`.
  (see [platforms.md](platforms.md), [cli.md](cli.md#rbit-init))
- **transport**: the host launcher used to run a toolchain program, such as a
  Wine `cl` wrapper or the native `rc`. `--compiler-transport` and
  `--resource-transport` must be given together. (see
  [platforms.md](platforms.md), [cli.md](cli.md#rbit-setup))
- **probe**: a bounded test run of the host backend: a compiler child process
  under Wine, or a fresh logon session with a lineage drive on native Windows.
  `rbit setup` probes the backend, `rbit doctor --execute-probe` runs it on
  demand, and the native backend reruns it before preparing a producer arena.
  (see [cli.md](cli.md#rbit-doctor), [windows.md](windows.md))
- **Job Object**: the Windows kernel object that groups a producer's process
  tree. The native backend starts each producer suspended inside a kill-on-close
  Job Object so the whole tree is gone before its private drive is released.
  (see [windows.md](windows.md))
- **nonce**: the 64-hex invocation nonce that `--action-nonce` pairs with
  `--action-receipt` so a GitHub Action run can be tied to one invocation. (see
  [cli.md](cli.md#rbit-verify), [action.md](action.md))
