#!/usr/bin/env bash
#
# Copyright (c) 2018 Martin Storsjo
# Copyright (c) 2025 archaic-msvc developers
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

set -e

# Adapted for MSVC 4.20 (itsmattkc/msvc420 portable layout)

MSVC_ROOT="$(cd -- "$(dirname -- "$0")/../.." && printf '%s\n' "$(pwd)")"
MSVC_ROOT=${MSVC_ROOT//\//\\}
export INCLUDE="${MSVC_ROOT}\\include;${MSVC_ROOT}\\mfc\\include"
export LIB="${MSVC_ROOT}\\lib;${MSVC_ROOT}\\mfc\\lib"
export LIBPATH="$LIB"
export WINEPATH="${MSVC_ROOT}\\bin;${MSVC_ROOT}\\bin\\winnt"

# LINK.EXE, CL, C1XX, C2, C1, CVPACK and MSPDB41 all import qsort (and bsearch,
# _atoldbl, _control87, setlocale, rand, malloc) from MSVCRT40.dll. Wine ships a
# builtin msvcrt40, and ITS qsort differs from Microsoft's the moment an array
# exceeds the insertion-sort cutoff of 8: Wine leaves such a range in place where
# Microsoft's swaps the pivot to the low slot. That single difference reorders
# LINK's import-thunk arrays and perturbs C2's register allocator.
# Forcing the native redistributable (4.10.6038, taken from the MSVC 5.0 RTM
# redist, dropped next to the tools so Wine finds it in the application
# directory) preserves the sorting-dependent output of the Microsoft runtime.
export WINEDLLOVERRIDES="msvcrt40=n;msvcrt20=n${WINEDLLOVERRIDES:+;$WINEDLLOVERRIDES}"

MSVC_EDITBIN_BIN="${MSVC_ROOT}\\bin\\EDITBIN.EXE"
MSVC_NMAKE_BIN="${MSVC_ROOT}\\bin\\NMAKE.EXE"
MSVC_CVPACK_BIN="${MSVC_ROOT}\\bin\\CVPACK.EXE"
MSVC_CL_BIN="${MSVC_ROOT}\\bin\\CL.EXE"
MSVC_CVTRES_BIN="${MSVC_ROOT}\\bin\\CVTRES.EXE"
MSVC_MC_BIN="${MSVC_ROOT}\\bin\\MC.EXE"
MSVC_DUMPBIN_BIN="${MSVC_ROOT}\\bin\\DUMPBIN.EXE"
MSVC_LIB_BIN="${MSVC_ROOT}\\bin\\LIB.EXE"
MSVC_MIDL_BIN="${MSVC_ROOT}\\bin\\MIDL.EXE"
MSVC_RC_BIN="${MSVC_ROOT}\\bin\\RC.EXE"
MSVC_LINK_BIN="${MSVC_ROOT}\\bin\\LINK.EXE"
