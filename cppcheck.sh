#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ge 1 && ($1 = "-h" || $1 = "--help") ]]; then
    echo >&2 "Usage: $0 [custom CMake arguments...]"
    echo >&2 "Will analyze the library, including tests, with cppcheck."
    echo >&2 "Any arguments to the script will be passed verbatim to CMake in addition to"
    echo >&2 "the arguments necessary for this script."
    exit 0
fi

sourcedir="$(dirname "$0")"
builddir="$(mktemp -d)"

trap "rm -rf '$builddir'" EXIT

nthreads="$(nproc || echo -n "")"
if [[ -z $nthreads ]]; then
    nthreads=4
    echo >&2 "Warning: Could not determine number of CPU cores, using $nthreads"
fi

cmake -S "$sourcedir" -B "$builddir" -DCMAKE_BUILD_TYPE=Debug \
	-DCMAKE_EXPORT_COMPILE_COMMANDS=On "$@"

# Note: performance checking produces only false positives, and
# unusedFunction is incompatible with parallel execution.
cppcheck --project="$builddir/compile_commands.json" -j"$nthreads" -q \
	--enable=warning,information,portability --suppress="*:*google*"
