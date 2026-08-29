# Native Windows and MSVC 4.2

This is the canonical guide to ReproBit's native Windows path. macOS and Linux
can test portable behavior, but only Windows can exercise the logon-session
drive and Job Object lifecycle used by this backend.

## Set up the compiler

The compiler is not stored in this repository, a GitHub cache, or workflow
artifact. From a ReproBit checkout, install the package, then provision and
check the known MSVC 4.2 files. These commands use PowerShell:

```console
rbit toolchain provision --destination C:\toolchains\msvc42 --no-save
rbit doctor --backend windows_native_v1 `
  --toolchain-profile msvc_4_2 `
  --toolchain-root C:\toolchains\msvc42 `
  --execute-probe
```

ReproBit does not download authenticated inputs from inside the producer tree.
Provision the compiler and obtain any protected reference files before starting
the hermetic build.

## How the private drive works

The native lineage broker uses
`CreateProcessWithLogonW(LOGON_NETCREDENTIALS_ONLY)` to create its isolated
logon session without account secrets or special token privileges. Windows
keeps the caller's local identity, does not validate the deliberately unusable
network credentials, and creates a fresh LSA logon session. ReproBit verifies
that fresh identity before defining the private drive; an ordinary drive
mapping is not a substitute.

The broker and every producer descendant intentionally receive unusable default
network credentials. Authenticated toolchain acquisition, dependency download,
or reference retrieval must therefore finish before `rbit build` or
`rbit verify`. The build itself should use only its admitted local inputs.

The producer starts suspended and enters a kill-on-close Job Object before its
first instruction. The broker keeps the drive until that complete process tree
is empty. The execution probe checks that a descendant sees the private path;
missing APIs, redirected roots, drive conflicts, failed session isolation, or
escaped descendants are hard failures.

## What the provisioner trusts

The provisioner uses sparse checkouts at these exact upstream revisions:

- `archaic-msvc/msvc420@b42c244f0a83ba15ba2ffb62b0dc240d7b2dea50`
- `archaic-msvc/msvc500@8abf95ce980161ad87b0b02402269cce76988953`
  for `MSVCRT40.dll` and `msvcrt20.dll` only

These pins are profile inputs, not script-only constants. A generated toolchain
lock records their origin: the 4.2 producers, headers, libraries, and
`RCDLL.DLL` come from `msvc420`; only the two listed C runtime DLLs come from
`msvc500`. Using those two DLLs does not constitute end-to-end MSVC 5.0 support.
The lock records that claim; it is not proof that the files were acquired.

It copies only admitted producers, runtime files, headers, and libraries. It
checks out the stated revisions, asserts the upstream C2 digest and both patch
preimages, applies the two required five-byte patches, then checks every
admitted file and complete portable input tree before atomically publishing the
destination. Re-running the command authenticates an existing exact destination
and performs no checkout. An inexact existing destination is never modified.

These upstream repositories do not include a license grant for the Microsoft
binaries. Their public availability is not permission to redistribute or use
them. Keep the payload external and confirm that your use is authorized.

## What CI proves

The public native gate currently uses GitHub's `windows-2022` runner label. That
label selects an OS family, not an immutable image revision, so every run records
`ImageOS`, `ImageVersion`, the Windows build, and Python architecture. The job
rebuilds and re-authenticates the toolchain, runs the private-drive and process-
lifetime tests, and compiles through the real MSVC 4.2 child chain. It uploads
only tests and diagnostic logs.

This is end-to-end host evidence for MSVC 4.2. ReproBit recognizes MSVC 5.0 RTM
and service-pack profiles, but those profiles do not yet have an equivalent
public compiler-and-fixture gate.
