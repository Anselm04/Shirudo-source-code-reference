#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6151 -- shirudo drops the personality its caller gives it: started
# under setarch --uname-2.6, which makes uname() report a 2.6 release, it
# still reads the kernel's own, the one the tree selector compares.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v setarch >/dev/null 2>&1 || test_skip_all "no setarch"
setarch "$(uname -m)" --uname-2.6 true 2>/dev/null ||
	test_skip_all "setarch cannot set UNAME26"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
release() {
	"$@" "$SHIRUDO_BIN" status --json --include-system 2>/dev/null |
		python3 -c '
import json, sys
print(json.load(sys.stdin)["system"]["kernel_release"])
'
}

test_expect_success 'the caller sees a 2.6 release under UNAME26' '
	setarch "$(uname -m)" --uname-2.6 uname -r >"$W/caller" &&
	grep -q "^2\.6\." "$W/caller"
'
test_expect_success 'shirudo reads the kernel release all the same' '
	release env >"$W/plain" &&
	release setarch "$(uname -m)" --uname-2.6 >"$W/uname26" &&
	[ -s "$W/plain" ] &&
	cmp -s "$W/plain" "$W/uname26" &&
	! grep -q "^2\.6\." "$W/uname26"
'
test_done
