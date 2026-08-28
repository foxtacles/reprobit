#!/usr/bin/env bash
# ReproBit compiler-visible path proxy.
#
# Direct classic MSVC producers must receive only the committed DOS-path
# contract.  This proxy is copied under the conventional cl/rc/link/lib names
# and maps every run-private source/build/toolchain argument before invoking
# the admitted frontend.

set -euo pipefail

case "${0##*/}" in
  cl) logical_variable=REPROBIT_LOGICAL_CL ;;
  rc) logical_variable=REPROBIT_LOGICAL_RC ;;
  link) logical_variable=REPROBIT_LOGICAL_LINK ;;
  lib) logical_variable=REPROBIT_LOGICAL_LIB ;;
  *)
    printf 'ReproBit path proxy has an unsupported tool name: %s\n' "$0" >&2
    exit 64
    ;;
esac

transport=${REPROBIT_WINE_MSVC_TRANSPORT:-}
logical_program=${!logical_variable:-}
physical_drive=${REPROBIT_PHYSICAL_DRIVE_ROOT:-}
logical_drive=${REPROBIT_LOGICAL_DRIVE_ROOT:-}
physical_toolchain=${REPROBIT_PHYSICAL_TOOLCHAIN_ROOT:-}
logical_toolchain=${REPROBIT_LOGICAL_TOOLCHAIN_ROOT:-}
if [[ ! -x "$transport" || -z "$logical_program" \
    || -z "$physical_drive" || -z "$logical_drive" \
    || -z "$physical_toolchain" || -z "$logical_toolchain" ]]; then
  printf 'ReproBit path proxy environment is incomplete\n' >&2
  exit 64
fi
rewritten=()

# Emit producer-visible DOS paths directly.  The admitted archaic-msvc
# transport conditionally converts host paths only when their host dirname
# happens to exist.  Depending on that heuristic would make an otherwise valid
# logical seat such as Z:\src fail on a host without /src.  Drive-qualified
# operands bypass that heuristic entirely.  Preserve the historical lower-case
# z: spelling for the legacy virtual-root backend; other committed drives keep
# their declared spelling.
logical_replacement() {
  local value=$1
  value=${value//\\//}
  if [[ "$value" != [A-Za-z]:* ]]; then
    printf 'ReproBit path proxy replacement is not a DOS path\n' >&2
    exit 65
  fi
  case "$value" in
    [zZ]:*) value=z:${value:2} ;;
  esac
  printf '%s' "$value"
}

toolchain_replacement=$(logical_replacement "$logical_toolchain")
drive_replacement=$(logical_replacement "$logical_drive")
for argument in "$@"; do
  if [[ "$argument" == *"$physical_toolchain"* ]]; then
    original=$argument
    argument=${argument//"$physical_toolchain"/"$toolchain_replacement"}
    if [[ "$argument" == "$original" ]]; then
      printf 'ReproBit path proxy could not map a toolchain path\n' >&2
      exit 65
    fi
  fi
  if [[ "$argument" == *"$physical_drive"* ]]; then
    original=$argument
    argument=${argument//"$physical_drive"/"$drive_replacement"}
    if [[ "$argument" == "$original" ]]; then
      printf 'ReproBit path proxy could not map a drive path\n' >&2
      exit 65
    fi
  fi
  # VC 4.x accepts ordinary drive-qualified operands with forward slashes, but
  # its attached /FI parser treats ``z:/...`` as drive-relative and diagnoses
  # the invalid ``Z:z:/...`` path.  Only that exact compiler option needs DOS
  # separators; keeping source tokens as z:/ preserves their CodeView spelling.
  if [[ "$logical_variable" == REPROBIT_LOGICAL_CL ]]; then
    case "$argument" in
      /FI[A-Za-z]:/*|-FI[A-Za-z]:/*)
        option=${argument:0:3}
        value=${argument:3}
        value=${value//\//\\}
        argument=${option}${value}
        ;;
    esac
  fi
  rewritten+=("$argument")
done

exec "$transport" "$logical_program" "${rewritten[@]}"
