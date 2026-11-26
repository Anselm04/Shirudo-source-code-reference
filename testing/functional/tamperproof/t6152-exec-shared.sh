#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6152 -- the runtime binary is not exec'd by a task that shares its root
# and working directory with another process, which could chroot or chdir
# the authorized command while it runs: the exec is refused and counted
# as ExecShared, and an exec of any other program that way still works.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
H=helper/test-exec-shared
[ -x "$H" ] || test_skip_all "test-exec-shared helper not built"
RUNTIME=$(runtime_binary)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
print(json.load(sys.stdin)["tamper_attempts"]["counters"][sys.argv[1]])
' "$1"
}
before=$(counter ExecShared) || test_skip_all "no tamper counters"

test_expect_success 'another program execs with a shared file system context' '
	"$H" /bin/true
'
test_expect_success 'the runtime binary does not, and the refusal counts' '
	if "$H" "$RUNTIME" version >"$W/out" 2>"$W/err"; then false; fi &&
	grep -q "Permission denied" "$W/err" &&
	[ "$(counter ExecShared)" -gt "$before" ]
'
test_expect_success 'and runs as before without the sharing' '
	"$RUNTIME" version >/dev/null
'
test_done
