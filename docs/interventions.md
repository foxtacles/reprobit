# Interventions

An intervention is one committed JSON record under `reprobit/interventions/`
that declares a reviewed adjustment to how the clean source is compiled,
linked, or post-processed. This page lists every intervention kind and every
closed enumeration the record schema admits, together with the label
`rbit explain` prints for it and its class in the [cost model](costs.md). The
authoritative definitions are `schemas/intervention-document-v3.schema.json`
and `reprobit.schema`; the cost mapping is `reprobit.costs.CostModel`.

## Common fields

Every kind shares the fields of `reprobit.schema.InterventionBase`:

| Field | Meaning |
|---|---|
| `id` | Stable identifier; other records refer to it. |
| `version` | Record version, currently always `1`. |
| `kind` | Discriminator that selects the typed record (tables below). |
| `scope` | Target, optional translation unit, optional function. |
| `rationale` | Free text, 1–4096 characters, explaining why the adjustment exists. |
| `dependencies` | Identifiers of records this one needs; a record cannot depend on itself. |
| `beneficiaries` | Function scopes that share this intervention's cost. Only target- or TU-scoped records may list them; each must stay within the record's target (and translation unit, when scoped to one). |

`rbit explain` prints one line per intervention as
`ID: <label>, cost=<points>, scope=<target/tu/function>`. The label is the
kind with underscores replaced by spaces and title-cased; for classic recipes
it is the family name, capitalized, followed by `adjustment`
(see `reprobit.cli_project._human_intervention_label`,
`reprobit.report_html_format.human_label`).

## Intervention kinds

| `kind` | `rbit explain` label | Cost class (points) | Typed fields | Meaning |
|---|---|---|---|---|
| `state_carrier` | State Carrier | State carrier (1) | `carrier` | A declared source element that changes compiler state before the function that matters (see `reprobit.schema.StateCarrierIntervention`, [costs.md](costs.md)). |
| `generated_supplier` | Generated Supplier | Generated supplier (5) | `supplier` | Names one generated supplier unit by identifier; `rbit import cmake` can seat such an item with `reprobit_insert_link_item` (see `reprobit.schema.GeneratedSupplierIntervention`, [cmake.md](cmake.md), [costs.md](costs.md)). |
| `metadata_normalization` | Metadata Normalization | Generated supplier (5) | `field`, `value` | Sets one named metadata field to a fixed integer or string value (see `reprobit.schema.MetadataNormalizationIntervention`). |
| `link_ordering` | Link Ordering | Link ordering (10) | `item_ids` (at least 2) | Fixes the order of existing compiler-produced units at link time (see `reprobit.schema.LinkOrderingIntervention`, [costs.md](costs.md)). |
| `equal_body_donor` | Equal Body Donor | Equal-body donor (25) | `donor_artifact`, `donor_symbol`, `expected_size` | Installs a same-symbol donor body of the expected size (see `reprobit.schema.EqualBodyDonorIntervention`). |
| `structural_donor` | Structural Donor | Structural donor (50) | `mode`, `donor_artifact`, `donor_symbol` | A donor install that also needs structural handling selected by `mode` (table below) (see `reprobit.schema.StructuralDonorIntervention`). |
| `cross_tu_donor` | Cross Tu Donor | Cross TU or Overlay (100) | `donor_translation_unit`, `donor_artifact`, `donor_symbol` | A donor taken from a different translation unit (see `reprobit.schema.CrossTuDonorIntervention`). |
| `semantic_rewrite` | Semantic Rewrite | Semantic rewrite (250) | `method`, `source_artifact`, `rewrite_digest` | An instruction-level rewrite of a compiler-produced body, selected by `method` (table below) (see `reprobit.schema.SemanticRewriteIntervention`). |
| `binary_surgery` | Binary Surgery | Binary surgery (500) | `method`, `source_artifacts` (at least 1), `output_digest` | Byte-level composition from one or more artifacts, selected by `method` (table below) (see `reprobit.schema.BinarySurgeryIntervention`). |
| `classic_recipe` | `<Family> adjustment` | By family (next section) | `family`, `role`, `build_target`, `symbol`, `parameters` | A data-only invocation of one closed classic recipe family (see `reprobit.schema.ClassicRecipeIntervention`). |
| `legacy.oracle_install` | Legacy.Oracle Install | Oracle install (10,000) | `allowlist_digest`, `proof_receipt_digest`, `preimage_digest`, `oracle_body_digest`, `oracle_target`, `oracle_address`, `ranges`, `byte_count` | Copies declared byte ranges from a reference image; every range's preimage, output, and oracle lengths must match, and the result is always a quarantine (see `reprobit.schema.LegacyOracleInstallIntervention`, [authenticity.md](authenticity.md)). |

## Classic recipe records

A `classic_recipe` record names a `family`, a `role`, its `build_target`, an
optional `symbol`, and canonically ordered `parameters`. The validator in
`reprobit.schema.ClassicRecipeIntervention` enforces:

- role `function` requires a `symbol`, a scope whose function equals that
  symbol, and exactly one dependency: the primary donor;
- roles `donor` and `project` must not name a symbol or a function scope;
  `donor` requires translation-unit scope, `project` requires target scope;
- parameter names may not contain `bytes`, `payload`, `oracle_path`,
  `reference_path`, `callable`, `script`, `python`, or `template`
  (`_FORBIDDEN_CLASSIC_FIELDS`): recipes carry no payload and no code;
- `retail_exact_simulated_elision` is rejected here and must be represented
  by a `legacy.oracle_install` quarantine instead.

### `ClassicRecipeRole`

| Value | Meaning |
|---|---|
| `function` | The recipe produces one function of a candidate object from a donor. |
| `donor` | The recipe renders a private donor compile for one translation unit. |
| `project` | The recipe applies at target scope (source overlay, image, archive). |

### `ClassicRecipeFamily`

Each family has a registered semantic contract in
`reprobit.classic.semantic_contracts.CLASSIC_SEMANTIC_CONTRACTS` unless noted.
Points are the per-unit weight of the family's cost class.

#### Donor-rendering families (role `donor`)

Contract `classic.donor-isolation.<family>.v1`; obligations
`donor.fresh_compile`, `donor.private_artifact`, `donor.runtime_inputs_bound`.
Parameters are validated and rendered by `reprobit.classic_donors`; all of
them carry `emission_policy` = `non_emitting_declarations_only` and
`generated_header_sha256`.

| Family | `rbit explain` label | Cost class (points) | What it renders |
|---|---|---|---|
| `declaration_shape` | Declaration shape adjustment | State carrier (1) | A declaration-only shape of `classes` classes and `functions` unused inline members (no storage, code, data, strings, vtables, or directives), force-included (see `reprobit.declaration_shapes.generate_shape`). |
| `pad_shape` | Pad shape adjustment | Generated supplier (5) | A grid of `classes` classes each with `functions_per_class` unused inline members, force-included; optional `donor_source` (see `reprobit.declaration_shapes.generate_pad_shape`). |
| `forward_declaration_run` | Forward declaration run adjustment | State carrier (1) | `count` forward declarations with stem `prefix` and `width`, at `placement` `prefix`, `after_includes`, `force_include`, or `suffix`. |
| `extern_run_pair` | Extern run pair adjustment | State carrier (1) | A header run and a seat run of `extern int` object declarations (`header_prefix`/`header_count`, `seat_prefix`/`seat_count`, `width`) (see `reprobit.declaration_shapes.generate_extern_run`). |
| `forward_run_with_shape` | Forward run with shape adjustment | Generated supplier (5) | A forward run followed by a declaration shape; optional cross-TU carrier fields pin the donor source and its rendering. |
| `declaration_run_triple` | Declaration run triple adjustment | State carrier (1) | Up to three forward runs seated `pre`, `post`, and `eof`, each with its own stem and count. |
| `prefix_forward_after_includes_extern` | Prefix forward after includes extern adjustment | State carrier (1) | A forward run before the includes plus an extern run after them (`forward_*` and `extern_*` parameters). |
| `donor_source_overlay` | Donor source overlay adjustment | Cross TU or Overlay (100) | A donor-private source overlay; it can never enter a primary project compiler seat (see `ClassicRecipeFamily` docstring). |

#### Function families (role `function`)

Contract `classic.binary-transform.<family>.v1`; obligations
`binary.closed_validator`, `binary.input_closure`,
`binary.semantic_equivalence`. Each is dispatched to one composer in
`reprobit.classic_project`; the composer never reads a reference image.

| Family | `rbit explain` label | Cost class (points) | What the composer does |
|---|---|---|---|
| `equal_body_strict` | Equal body strict adjustment | Equal-body donor (25) | Copies one equal-size COMDAT code body from the donor into the seed object; `.debug$F`/`.debug$S` closure with literally equal relocation tuples (see `classic.composition.compose_equal_body_comdat`). |
| `equal_body_eh_structural_local` | Equal body eh structural local adjustment | Structural donor (50) | Same equal-size copy with `.debug$S`/`.xdata$x` closure for exception-handling structures (see `classic.composition.compose_equal_body_comdat`). |
| `equal_body_eh_reloc_layout` | Equal body eh reloc layout adjustment | Structural donor (50) | Equal-size copy handled by the same composer with relocation-layout handling (see `classic.composition.compose_equal_body_comdat`, [costs.md](costs.md)). |
| `same_slot_resize` | Same slot resize adjustment | Structural donor (50) | Installs a donor body of a different size in the same 16-byte linked slot, repairing every dependent COFF record (see `classic.composition.compose_same_slot_resize`). |
| `retail_exact_reloc_divergent` | Retail exact reloc divergent adjustment | Cross TU or Overlay (100) | Splices a donor body whose external relocation targets diverge, under a closed declarative relocation contract (see `classic.composition.produce_reloc_divergent_candidate`). |
| `retail_exact_source_equal_body` | Retail exact source equal body adjustment | Cross TU or Overlay (100) | Installs one equal-size body from a closed source refactor, adding source identity and closure pins (see `classic.composition.produce_source_equal_body_candidate`). |
| `retail_exact_source_target_closure` | Retail exact source target closure adjustment | Cross TU or Overlay (100) | Extracts one compiler-produced target from a source-closed donor whose source window is proved byte-identical (see `classic.composition.produce_source_target_closure_candidate`). |
| `retail_exact_cross_tu_complete_target_resize` | Retail exact cross tu complete target resize adjustment | Cross TU or Overlay (100) | Normalizes one complete cross-TU COMDAT into an owner-TU carrier; no partial code ranges (see `classic.composition.produce_cross_tu_complete_target_resize_candidate`). |
| `retail_exact_donor_rewriting` | Retail exact donor rewriting adjustment | Semantic rewrite (250) | Produces a rewrite of a freshly compiled donor body (see `classic.rewriting.produce_donor_rewriting_candidate`). |
| `retail_exact_composed_rewriting` | Retail exact composed rewriting adjustment | Semantic rewrite (250) | Applies a reordering, then regional register bijections, then reversed compares (see `classic.rewriting.produce_composed_rewriting_candidate`). |
| `retail_exact_register_bijection` | Retail exact register bijection adjustment | Semantic rewrite (250) | Fixed-width register renaming of a fresh donor body, proved sound against its control flow (see `classic.register_candidates.produce_register_bijection_candidate`). |
| `retail_exact_register_bijection_reencoding` | Retail exact register bijection reencoding adjustment | Semantic rewrite (250) | Length-changing register renaming with EBP admitted (see `classic.register_candidates.produce_register_bijection_reencoding_candidate`). |
| `retail_exact_web_recolour` | Retail exact web recolour adjustment | Semantic rewrite (250) | Recolours a def-use web of the seed's own body; the donor is a provenance witness only (see `classic.scheduling.produce_web_recolour_candidate`). |
| `retail_exact_instruction_mosaic` | Retail exact instruction mosaic adjustment | Binary surgery (500) | Draws same-offset complete instructions from several declaration-carrier compiles of the same translation unit (see `classic.composition.produce_instruction_mosaic_candidate`). |
| `retail_exact_same_tu_instruction_hybrid_resize` | Retail exact same tu instruction hybrid resize adjustment | Binary surgery (500) | Composes two source-identical, declaration-carrier same-TU donors (see `classic.composition.produce_same_tu_instruction_hybrid_resize_candidate`). |

#### Project-level families (role `project`)

| Family | `rbit explain` label | Cost class (points) | Contract and meaning |
|---|---|---|---|
| `source_overlay_graph` | Source overlay graph adjustment | Cross TU or Overlay (100) | Contract `classic.source-overlay-ancestry.v1`, obligations `overlay.*`; rendered bytes may enter the primary compiler seat with origin `certified-project-overlay` after the closed typed-source proof (see `ClassicRecipeFamily` docstring, `classic.project_overlay`). |
| `image_metadata` | Image metadata adjustment | Generated supplier (5) | Contract `classic.image-metadata.v1`; obligations `image.candidate_only`, `image.logic_bytes_unchanged`, `image.metadata_only`. |
| `image_link_order` | Image link order adjustment | Link ordering (10) | Contract `classic.image-link-order.v1`; obligations `image.candidate_only`, `image.import_binding_preserved`, `image.semantic_equivalence`. |
| `image_binary_repack` | Image binary repack adjustment | Binary surgery (500) | Contract `classic.image-binary-repack.v1`; obligations `image.byte_conservation`, `image.candidate_only`, `image.fixups_preserved`, `image.semantic_equivalence`. |
| `archive_admission` | Archive admission adjustment | Link ordering (10) | No semantic contract is registered; the typed declaration is preserved but the terminal producer is not implemented (see `reprobit.classic_project` family coverage). |

#### Quarantine-only family

| Family | `rbit explain` label | Cost class | Meaning |
|---|---|---|---|
| `retail_exact_simulated_elision` | not printed as a classic recipe | not costable as a classic recipe | Must be represented and executed by the quarantined simulated-elision composer, the only classic producer allowed to read reference-image bytes; its provenance is permanently ineligible for a clean verdict (see `classic.legacy_elision`, `reprobit.classic_quarantine`). |

### `StructuralMode` (field `mode` of `structural_donor`)

| Value | Meaning |
|---|---|
| `resize` | The donor body has a different size than the seed's. |
| `exception_handling` | Exception-handling structures need handling. |
| `relocation_layout` | Relocation layout needs handling. |
| `complete_target` | The complete target is taken from the donor. |

All four fall in the Structural donor class, 50 points per unit
([costs.md](costs.md): "Intact donor with resize, EH, or relocation-layout
handling"). `complete_target` also names the cross-TU complete-target
composer's mode in `reprobit.classic.composition`.

### `SemanticRewriteMethod` (field `method` of `semantic_rewrite`)

| Value | Classic composer with the same name |
|---|---|
| `register_bijection` | `reprobit.classic.register_bijection` (fixed-width register bijections). |
| `donor_rewrite` | `reprobit.classic.rewriting.produce_donor_rewriting_candidate`. |
| `web_recolour` | `reprobit.classic.scheduling.produce_web_recolour_candidate`. |
| `scheduling` | Schema value only; no module outside `reprobit.schema` refers to it. |
| `instruction_form` | Schema value only; no module outside `reprobit.schema` refers to it. |
| `floating_point` | Schema value only; no module outside `reprobit.schema` refers to it. |

All six fall in the Semantic rewrite class, 250 points per unit.

### `BinarySurgeryMethod` (field `method` of `binary_surgery`)

| Value | Classic composer with the same name |
|---|---|
| `instruction_mosaic` | `reprobit.classic.composition.produce_instruction_mosaic_candidate`. |
| `instruction_hybrid` | `reprobit.classic.composition.produce_same_tu_instruction_hybrid_resize_candidate`. |
| `text_repack` | `reprobit.classic.pe_text`. |
| `data_repack` | `reprobit.classic.coff_projection` and the classic runtime modules. |

All four fall in the Binary surgery class, 500 points per unit.

## Where to look next

- [costs.md](costs.md) explains how units, beneficiaries, and shared donors
  turn these classes into a project total.
- [authenticity.md](authenticity.md) explains which kinds can still yield a
  clean verdict and why oracle installs never do.
- [discovery.md](discovery.md) explains how `rbit discover grind` proposes
  the donor-rendering families automatically.
- [project-format.md](project-format.md) describes the surrounding record
  layout and the proof documents that certify each intervention.
