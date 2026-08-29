# Guided declaration discovery

This example shows how unused declarations can alter MSVC 4.2 output. ReproBit
tries four declaration combinations and finds the exact declaration shape
used to prepare the local reference object. A second run reuses all four
results; an extended request adds exactly one new state.

Discovery is a preview. A proposal is useful review evidence, but it is not a
proof, a source edit, or permission to add an intervention to a certified build.

Start with the [shared prerequisites](../README.md), then run these commands
from this directory:

```console
cd examples/declaration-discovery
rbit toolchain provision msvc_4_2
python prepare_reference.py
```

`prepare_reference.py` compiles `transform.cpp` with the campaign state that
contains three generated classes and ten generated function declarations, then
writes the untracked `reference.obj`. It accepts
`--toolchain-root` to override the compiler location remembered by ReproBit; run
`python prepare_reference.py --help` for all options.

## 1. Cold campaign

```console
rbit discover run campaign.json \
  --state-directory .sample-state \
  --report-json campaign.report.json \
  --jobs 4
python review_report.py campaign.report.json
```

ReproBit writes both `campaign.report.json` and the sibling
`campaign.report.html`. Open the HTML file for the guided visual review; use
`review_report.py` when a short terminal summary is more convenient.

Expected outcome:

- four declaration combinations are compiled and none are reused;
- one `whole_body` proposal matches `_transform`;
- the report and selected object artifacts are written locally; and
- the review output begins with `NON-CERTIFYING DISCOVERY REVIEW`.

The review helper only reads and summarizes the schema-validated report. It has
no apply or accept operation.

## 2. Resume unchanged work

Run the same `rbit discover run campaign.json ...` command again, followed by the
review command. The new report should say that nothing was rebuilt and all
four results were reused. Analysis still runs against the sealed reference.

## 3. Extend by one state

The extended request changes only the inclusive class-count limit and
`max_cells`:

```console
rbit discover run campaign-extended.json \
  --state-directory .sample-state \
  --report-json campaign-extended.report.json \
  --jobs 4
python review_report.py campaign-extended.report.json
```

Expected outcome: four results are reused and only the new fifth combination is built.
This is the same workflow used when a real campaign needs one more bounded
range without throwing away completed compiler work.

## What to inspect

- `campaign.json` fixes the symbols, declaration range, compiler switches, and
  search budget before work starts.
- `campaign.report.json` records every observed function and the exact inputs
  and implementation authority used for analysis.
- `.sample-state/cache/artifacts/` contains only objects selected by proposals.
- `review_report.py` shows each proposal's declarations, rationale, and artifact
  path without changing the project.

## Troubleshooting

- **`reference.obj` is absent:** run `python prepare_reference.py` first.
- **Wine or `wineserver` is unavailable:** install Wine and ensure both commands
  are on `PATH`. Native Windows does not need Wine.
- **The toolchain is rejected:** verify that the path is a complete
  archaic-msvc 4.2 installation with `bin/CL.EXE` and the platform wrapper.
- **A reference already exists:** the helper leaves it unchanged. Use
  `python prepare_reference.py --replace` only when you intentionally changed
  the source, campaign, or compiler installation.
- **The first campaign reports cache hits:** `.sample-state` contains an earlier
  run. Rename it to keep the old state, then run again with a fresh
  `.sample-state` directory.
- **No proposal matches:** regenerate `reference.obj` with the same toolchain and
  unchanged campaign arguments. Compiler version and switches are part of the
  experiment.

All generated files in this directory are disposable. None of them become
certified project authority automatically.
