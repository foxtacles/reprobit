# Repair after a shared-header edit

This small project starts with an exact MSVC 4.2 build and one saved compiler
adjustment. Both source files include `shared.h`.

From the ReproBit repository root, prepare the local compiler and reference
file, then check the starting point:

```console
cd examples/repair
rbit setup .
python prepare_reference.py
rbit verify .
```

Now add an unused forward declaration above the macros in `shared.h`:

```cpp
class RepairUnusedForward;
```

Then run:

```console
rbit repair .
```

`repair` detects that both source files may have been affected and discovers
that the old compiler adjustment is no longer needed. It removes that saved
guidance, rebuilds from scratch, and publishes the simpler project records and
exact output together. If the edit changes the program, nothing is published
and the previous exact output remains in place.

The authenticated native-Windows CI job runs both outcomes end to end. Generated
references and build state stay local and are ignored by Git.
