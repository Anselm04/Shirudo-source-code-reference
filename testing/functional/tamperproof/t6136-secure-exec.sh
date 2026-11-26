#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6136 -- nothing in the environment of whoever starts shirudo steers it.
# shirudo is static, with no program interpreter for LD_PRELOAD, LD_AUDIT
# or LD_LIBRARY_PATH to reach, and the kernel runs every executable of the
# runtime image in secure-exec mode, directly or as a script's interpreter,
# so its C library ignores the variables it would otherwise honour. The
# policy probe in the test runtime image reports the AT_SECURE it got; its
# copy outside the image is the control.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

PROBE=/run/shirudo/runtime/usr/bin/shirudo-policy-probe
BIN=$(runtime_binary)
[ -x "$PROBE" ] || test_skip_all "the runtime image has no policy probe"
[ -x "$BIN" ] || test_skip_all "cannot find the runtime shirudo"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

test_expect_success 'shirudo has no program interpreter' '
	python3 - "$BIN" <<"PY"
import struct, sys
data = open(sys.argv[1], "rb").read()
assert data[:4] == b"\x7fELF" and data[4] == 2, "not a 64-bit ELF"
phoff, = struct.unpack_from("<Q", data, 32)
phentsize, phnum = struct.unpack_from("<HH", data, 54)
for i in range(phnum):
    p_type, = struct.unpack_from("<I", data, phoff + i * phentsize)
    assert p_type != 3, "PT_INTERP"
PY
'

test_expect_success 'a runtime executable runs with AT_SECURE' '
	[ "$("$PROBE" secure)" = 1 ]
'

test_expect_success 'whatever loader variables it is started with' '
	out=$(LD_PRELOAD=/nonexistent.so LD_AUDIT=/nonexistent.so \
		LD_LIBRARY_PATH="$W" "$PROBE" secure) &&
	[ "$out" = 1 ]
'

test_expect_success 'and as the interpreter of a script' '
	printf "#!%s secure\n" "$PROBE" >"$W/script" &&
	chmod 0755 "$W/script" &&
	[ "$("$W/script")" = 1 ]
'

test_expect_success 'its copy outside the image runs without' '
	cp "$PROBE" "$W/probe" &&
	[ "$("$W/probe" secure)" = 0 ]
'

test_expect_success 'a library variable that names a file is refused' '
	for v in TSS2_LOGFILE SSLKEYLOGFILE; do
		! env "$v=$W/$v" "$BIN" status >"$W/out" 2>&1 &&
		grep -q "bootstrap override $v is forbidden" "$W/out" &&
		[ ! -e "$W/$v" ] || exit 1
	done
'

test_done
