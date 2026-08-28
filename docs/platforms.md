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

Wine workers own private prefixes and process groups. Native Windows keeps controller checks on
sealed physical roots; only producer argv and cwd use the logical drive. Each producer tree runs
in a fresh, proved LSA logon session: a contained broker verifies that Windows changed the token's
`AuthenticationId`, then uses `DefineDosDeviceW` only in that session-local namespace. The real
producer starts suspended, joins a nested kill-on-close Job Object before its first instruction,
and resumes only after admission. The broker retains the mapping until the Job reports zero active
processes, so an early-exiting producer cannot strand a descendant without its logical drive.
`rbit doctor --execute-probe` performs a bounded mutation probe through this complete path. The
inner broker, not the controller's unrelated local namespace, is authoritative for drive conflicts.
Missing native APIs, redirected roots, fresh-session drive conflicts, failed AuthenticationId
isolation, Job admission failures, and absent descendant visibility are required failures.

The repository's public CI runs the portable unit, backend-primitive, and packaging matrix on
Ubuntu, macOS, and Windows. A dedicated `windows-2022` gate provisions the external Archaic MSVC
4.2 authority at pinned revisions, authenticates it, runs the lineage-drive/process checks,
and compiles a C++ object through the real CL -> C1XX -> C2 child chain. Compiler bytes are neither
committed nor cached nor uploaded. That focused smoke proves the native execution primitive, not a
project's full cold byte-identity verdict; project certification still requires its locked
toolchain, reference oracles, and cold fixture on the intended host. A local Docker smoke counts
only when the Docker daemon is reachable; finding the Docker client alone is not Linux execution
evidence.
