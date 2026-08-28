# Platforms and logical paths

Classic compilers can treat absolute source and include spellings as code-generation inputs.
ReproBit therefore reproduces complete compiler-visible strings rather than merely equalizing
their lengths.

Each run creates a private physical arena and maps stable DOS seats for source, output, and
toolchain trees. The same `CompileContext` supplies argv, cwd, environment, response-file paths,
include order, force-includes, object paths, and PDB paths to production, donor, sweep, and control
compiles.

The portable source manifest hashes checked-out bytes, including line endings. Projects intended
to verify on more than one host should declare text normalization in `.gitattributes` and must not
depend on a runner's `core.autocrlf` setting. A platform checkout that changes admitted bytes is a
source-manifest failure, not an equivalent source tree.

Wine workers own private prefixes and process groups. Native Windows owns each producer tree with
a kill-on-close Job Object and maps the logical drive through an anonymous, process-private Object
Manager DeviceMap; it never uses the logon-visible `DefineDosDeviceW` namespace. Every directly
supervised Windows child starts suspended, joins its Job Object, receives that exact private map,
and only then resumes. `rbit doctor --execute-probe` performs a bounded mutation probe on Windows:
an assigned child must pass the map to its own descendant before the backend is admitted. Missing
native APIs, WOW64 controllers, occupied drive letters, assignment failures, and absent descendant
visibility are required failures.

The repository's public CI runs the portable unit, backend-primitive, and packaging matrix on
Ubuntu, macOS, and Windows. A dedicated `windows-2022` gate provisions the external Archaic MSVC
4.2 authority at pinned revisions, authenticates it, runs the DeviceMap/process-lineage checks,
and compiles a C++ object through the real CL -> C1XX -> C2 child chain. Compiler bytes are neither
committed nor cached nor uploaded. That focused smoke proves the native execution primitive, not a
project's full cold byte-identity verdict; project certification still requires its locked
toolchain, reference oracles, and cold fixture on the intended host. A local Docker smoke counts
only when the Docker daemon is reachable; finding the Docker client alone is not Linux execution
evidence.
