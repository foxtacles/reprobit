# MSVC 4.2 Wine transport snapshot

The five locked shell transports and their `msvcenv.sh` setup helper are
host-side files. They contain no Microsoft compiler, runtime, header, or
library payload. ReproBit ships their fixed bytes so one authenticated project
toolchain lock can be checked on both POSIX and native Windows hosts; the
native host does not execute them.

The copyright and permissive license notice inherited from the archaic-msvc
developers and Martin Storsjo is preserved in every transported file. The
compiler payload itself is still provisioned only from the repository
revisions pinned by ReproBit's MSVC 4.2 profile.
