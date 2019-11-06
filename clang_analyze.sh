#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ge 1 && ($1 = "-h" || $1 = "--help") ]]; then
    echo >&2 "Usage: $0 [custom CMake arguments...]"
    echo >&2 "Will compile the library, including tests, using the Clang static analyzer."
    echo >&2 "Any arguments to the script will be passed verbatim to CMake in addition to"
    echo >&2 "the arguments necessary for this script."
    exit 0
fi

#   These are the checkers that are enabled on top of the default ones
enable_checkers=(
    alpha.core.BoolAssignment
    alpha.core.CallAndMessageUnInitRefArg
    alpha.core.CastSize
    alpha.core.CastToStruct
    alpha.core.Conversion
    alpha.core.DynamicTypeChecker
    alpha.core.FixedAddr
    alpha.core.IdenticalExpr
    alpha.core.PointerArithm
    alpha.core.PointerSub
    alpha.core.SizeofPtr
    alpha.core.StackAddressAsyncEscape
    alpha.core.TestAfterDivZero
    alpha.cplusplus.DeleteWithNonVirtualDtor
    alpha.cplusplus.UninitializedObject
    alpha.security.ArrayBoundV2
    alpha.security.MallocOverflow
    alpha.security.MmapWriteExec
    alpha.security.ReturnPtrRange
    alpha.security.taint.TaintPropagation
    alpha.unix.SimpleStream
    alpha.unix.Stream
    alpha.unix.cstring.BufferOverlap
    alpha.unix.cstring.NotNullTerminated
    alpha.unix.cstring.OutOfBounds
    optin.cplusplus.VirtualCall
    security.FloatLoopCounter
    security.insecureAPI.bcmp
    security.insecureAPI.bcopy
    security.insecureAPI.bzero
    security.insecureAPI.rand
    security.insecureAPI.strcpy
)

checkers=""
for checker in ${enable_checkers[@]}; do
    echo "Extra checker enabled: ${checker}"
    checkers+="-enable-checker ${checker} "
done

sourcedir="$(dirname "$0")"
builddir="$(mktemp -d)"

trap "rm -rf '$builddir'" EXIT

nthreads="$(nproc || echo -n "")"
if [[ -z $nthreads ]]; then
    nthreads=4
    echo >&2 "Warning: Could not determine number of CPU cores, using $nthreads"
fi

CC=clang CXX=clang++ scan-build --use-cc=clang --use-c++=clang++ ${checkers} cmake -S "$sourcedir" -B "$builddir" -DCMAKE_BUILD_TYPE=Debug "$@"
scan-build --use-cc=clang --use-c++=clang++ ${checkers} make -j$(nproc) -C"$builddir"

