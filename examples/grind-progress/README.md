# Save progress across two independent mismatches

This ready-to-run sample starts with two source files whose functions both need
the same small compiler adjustment. It demonstrates the normal loop: preview,
save locally proven work, reach an exact executable, then verify once more from
scratch.

From the ReproBit repository root:

```console
cd examples/grind-progress
rbit setup .
python prepare_reference.py
rbit discover grind .
rbit discover grind . --accept-progress
rbit verify .
```

The preview report is
`.reprobit-state/reports/grind/project/report.html`. The accepted pass saves the
first function as local progress, rebuilds the second search against that new
state, and can then reach an exact project. Local progress is not certification:
the final `verify` remains the independent byte-identity gate.

The automatic search matches `reference/transform_one.obj` and
`reference/transform_two.obj` to their source filenames. The reference files are
generated locally with the authenticated MSVC 4.2 compiler and are ignored by
Git.
