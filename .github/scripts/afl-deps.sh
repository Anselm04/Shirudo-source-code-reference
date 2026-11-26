#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/afl-deps.sh -- build AFL++ for make -C testing afl into
# build/afl, or keep the build there when it is of the same commit and LLVM.
# The commit is of AFL++'s stable branch: no release takes LLVM 23 yet, and
# its compiler passes must be built for the clang the targets are built
# with. Needs curl, make, clang 23 and llvm-23-dev.
#
#   .github/scripts/afl-deps.sh

set -eu

commit=d0070729206a80a9af297b2341edd63f68fdac35
sha256=f6d36b6ff119e79a4b32b879ea87996b0b2f6d9e392ad9eee000fabad9b926f8
llvm_config=${LLVM_CONFIG:-llvm-config-23}
prefix=$PWD/build/afl
stamp="$commit $($llvm_config --version)"

if [ "$(cat "$prefix/.built" 2>/dev/null)" = "$stamp" ]; then
	exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSL --retry 3 -o "$work/afl.tar.gz" \
	"https://github.com/AFLplusplus/AFLplusplus/archive/$commit.tar.gz"
echo "$sha256  $work/afl.tar.gz" | sha256sum -c -
tar -xzf "$work/afl.tar.gz" -C "$work"

# Python, Nyx and Unicorn serve modes make -C testing afl does not use.
set -- LLVM_CONFIG="$llvm_config" NO_PYTHON=1 NO_NYX=1 NO_UNICORN_ARM64=1
make -C "$work/AFLplusplus-$commit" -j"$(nproc)" "$@" all
rm -rf "$prefix"
make -C "$work/AFLplusplus-$commit" "$@" PREFIX="$prefix" install
[ -x "$prefix/bin/afl-clang-fast" ] || {
	echo "afl-deps: AFL++ built without its LLVM mode" >&2
	exit 1
}
echo "$stamp" >"$prefix/.built"
