#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0007 -- .github/scripts/check-operator-linkage.sh: the libraries an
# operator binary may link and its own interpreter, against stub
# libraries, the ones it refuses, and the operator binaries when built.

cd "$(dirname "$0")/.."
. ./test-lib.sh
CC=${CC:-cc}
for t in "$CC" readelf; do
	command -v "$t" >/dev/null 2>&1 || test_skip_all "$t not installed"
done
ROOT=$(cd .. && pwd)
S=$ROOT/.github/scripts/check-operator-linkage.sh
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# Empty shared libraries in $W, each with its file name as its soname.
stub() {
	for so; do
		"$CC" -shared -fPIC -Wl,-soname,"$so" -o "$W/$so" -x c /dev/null
	done
}

# A program <name> in $W that needs every library named after it.
prog() {
	out=$1
	shift
	printf 'int main(void) { return 0; }\n' |
		"$CC" -x c - -x none -o "$W/$out" -Wl,--no-as-needed "$@"
}

check() {
	sh "$S" "$@" >"$W/out" 2>"$W/err"
}

stub libcrypto.so.3 libssl.so.3 libcurl.so.4 libtss2-esys.so.0 \
	libtss2-tctildr.so.0 libelf.so.1 libz.so.1 libluajit-5.1.so.2 \
	libfoo.so.1 libcurl-gnutls.so.4 libzstd.so.1 ld-linux-other.so.2
prog ok "$W/libcrypto.so.3" "$W/libssl.so.3" "$W/libcurl.so.4" \
	"$W/libtss2-esys.so.0" "$W/libtss2-tctildr.so.0" "$W/libelf.so.1" \
	"$W/libz.so.1" "$W/libluajit-5.1.so.2"
prog foo "$W/libz.so.1" "$W/libfoo.so.1"
interp=$(readelf -lW "$W/ok" |
	sed -n 's/.*\[Requesting program interpreter: \(.*\)\]$/\1/p')

test_expect_success 'the libraries an operator binary may link pass' '
	readelf -dW "$W/ok" | grep -q "Shared library: \[libluajit-5.1.so.2\]" &&
	check "$W/ok"
'

test_expect_success 'its own interpreter passes, another loader does not' '
	test -n "$interp" &&
	prog interp "$interp" &&
	check "$W/interp" &&
	prog loader "$W/ld-linux-other.so.2" &&
	! check "$W/loader" &&
	grep -q "links ld-linux-other.so.2" "$W/err"
'

test_expect_success 'a library outside the list fails and is named' '
	! check "$W/foo" &&
	grep -q "$W/foo links libfoo.so.1" "$W/err" &&
	! grep -q "libz.so.1" "$W/err"
'

test_expect_success 'a library named like an admitted one fails' '
	prog gnutls "$W/libcurl-gnutls.so.4" &&
	! check "$W/gnutls" &&
	grep -q "links libcurl-gnutls.so.4" "$W/err" &&
	prog zstd "$W/libzstd.so.1" &&
	! check "$W/zstd" &&
	grep -q "links libzstd.so.1" "$W/err"
'

test_expect_success 'every binary named is checked' '
	! check "$W/ok" "$W/foo" &&
	grep -q "$W/foo links libfoo.so.1" "$W/err"
'

test_expect_success 'a file readelf cannot read fails' '
	! check "$W/none"
'

test_expect_success 'no binary is a usage error' '
	rc=0 &&
	{ sh "$S" >/dev/null 2>&1 || rc=$?; } &&
	test "$rc" -eq 2
'

# A sanitized build also links the sanitizer runtimes, which gcc links
# as libraries of their own and clang into the binary, with the
# libraries they need; the runtime's symbols are there either way.
OPERATOR=$ROOT/shirudo
HELPER=$ROOT/tools/shirudo-build/shirudo-build
if [ -x "$OPERATOR" ] && [ -x "$HELPER" ] &&
   ! readelf -sW "$OPERATOR" | grep -qE ' __(asan|ubsan)_'; then
	test_expect_success 'the operator binaries pass' '
		sh "$S" "$OPERATOR" "$HELPER"
	'
else
	TAP_COUNT=$((TAP_COUNT + 1))
	printf 'ok %d - the operator binaries pass # SKIP not built, or sanitized\n' \
		"$TAP_COUNT"
fi

test_done
