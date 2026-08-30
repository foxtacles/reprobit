# Cost model v2

Costs describe how far a result is from an ordinary, checked-in source build. They are fixed by
the library and cannot be lowered by project configuration.

| Cost per unit | Class |
| ---: | --- |
| 0 | Native output, verification, receipts, and path normalization |
| 1 | Proven non-emitting declarations or compiler-state reservations |
| 5 | Emitting carriers, generated suppliers, or metadata normalization |
| 10 | Ordering existing compiler-produced units |
| 25 | Strict intact same-symbol compiler donor |
| 50 | Intact donor with resize, EH, or relocation-layout handling |
| 100 | Cross-unit donors or manifest-only source interventions |
| 250 | Instruction-level semantic rewrites |
| 500 | Mosaics, hybrids, repacks, or comparable binary surgery |
| 10,000 | Direct oracle-byte installation |

Most interventions contain one typed `intervention` unit. A `source_overlay_graph` instead
contains one `source_overlay_edit` unit for every declared top-level edit, one
`generated_translation_unit` unit for every generated translation-unit placement, and one
`link_admission` unit for every admission. Each of those units receives the class weight of 100.
Two edits therefore cost 200 whether they are represented by one intervention ID or two; ID
bundling cannot reduce the charge.

The project total sums typed units after deduplicating identical intervention IDs. Reports expose
both intervention and unit counts, distinguish direct function cost from allocated shared cost,
and retain non-additive exposure so shared work is never counted twice. The target and class
breakdowns are two views of that same total, not extra costs to add together. Function attribution
also conserves the total exactly: attributed function cost plus cost remaining at target or TU
scope equals the project total, even when equal shares are fractions.

Every beneficiary must be a unique, canonically ordered function scope in the intervention's
target (and in the same translation unit for a unit-scoped intervention). Project loading also
requires that scope to exist in the authoritative function universe established by direct
function interventions or oracle identities. Unknown “ghost” labels are rejected, so adding
an unanchored beneficiary label alone cannot dilute a shared function allocation.

A shared donor is charged once. Reusing the same donor for another function widens its
beneficiary list but does not charge the donor again; only newly added intervention work changes
the project total. Each beneficiary's exposure still shows the donor's full cost, and remains a
non-additive diagnostic.

An oracle install costs 10,000 points per intervention unit, not per referenced byte. Exact range
and byte counts remain separate authenticity evidence in the report; the cost score deliberately
ranks any reference-byte installation as a large departure from an ordinary build.

## Runtime work is not intervention cost

The score above measures semantic distance, not elapsed time or compiler-process count. For a
project-level `source_overlay_graph`, the closed validator derives a declaration counterfactual.
Declaration-only leaves add no compiler process. Strict source leaves add one evidence-only
counterfactual compile per exact source owner; strict headers conservatively select all ordinary
compilers because reader exposure is not independently sealed. Counterfactual objects are never
linked. These sparse invocations appear in producer progress and each obeys the compile timeout.
