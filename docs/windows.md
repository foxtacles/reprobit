# Native Windows and the MSVC 4.2 authority

ReproBit's Windows certification gate runs on the pinned `windows-2022`
GitHub-hosted image. A macOS or Linux checkout can test the portable contracts,
but it cannot certify Windows Object Manager DeviceMap and Job Object behavior.

The compiler is not stored in this repository, a GitHub cache, or workflow
artifacts. Provision the finite external authority after installing ReproBit:

```console
python scripts/provision_archaic_msvc42.py --destination C:\toolchains\msvc42
rbit doctor --backend windows_native_v1 \
  --toolchain-profile msvc_4_2 \
  --toolchain-root C:\toolchains\msvc42 \
  --execute-probe
```

The provisioner uses immutable sparse checkouts of:

- `archaic-msvc/msvc420@b42c244f0a83ba15ba2ffb62b0dc240d7b2dea50`
- `archaic-msvc/msvc500@8abf95ce980161ad87b0b02402269cce76988953`
  for `MSVCRT40.dll` and `msvcrt20.dll` only

These same two pins are reviewed profile repository inputs, not script-only
constants. A generated toolchain lock records them in `profile_sources`: every
admitted 4.2 producer, input tree, and `RCDLL.DLL` maps to `msvc420`, while the two
C runtime DLLs map to `msvc500`. This profile mapping is not proof of download.
The provisioner establishes acquisition by checking out those revisions and
matching its embedded exact file/tree authority after the authenticated C2 patch.

It copies only admitted producers, runtime files, headers, and libraries. It
asserts the upstream C2 digest and both patch preimages, applies the two required
five-byte patches, then checks every admitted file and complete portable input
tree before atomically publishing the destination. Re-running the command
authenticates an existing exact destination and performs no checkout. An
inexact existing destination is never modified.

These upstream repositories do not include a license grant for the Microsoft
binaries. Their public availability is not permission to redistribute or use
them. Keep the payload external and confirm that your use is authorized.

GitHub's runner label fixes the OS family, not an immutable image revision. The
native job records `ImageOS`, `ImageVersion`, the Windows build, and Python
architecture in every run. It uploads test and diagnostic logs only; the
toolchain itself is always rebuilt and re-authenticated in the job.
