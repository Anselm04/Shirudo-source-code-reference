#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6157 -- the pre-flight of init checks a kernel option the threat model
# assumes on the running kernel: module signatures. The test kernel,
# which signs its modules, passes it.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# Prints "ok" or "FAIL", then ": <detail>" when there is one, for the
# check $2 of the pre-flight JSON in $1.
check() {
	python3 -c '
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
for c in d["checks"]:
    if c["name"] == sys.argv[2]:
        print(("ok" if c["ok"] else "FAIL") +
              (": " + c["detail"] if c["detail"] else ""))
        sys.exit(0)
print("missing")
' "$1" "$2"
}

test_expect_success 'the test kernel passes the module signature check' '
	"$SHIRUDO_BIN" init --check-only --json >"$W/preflight.json" &&
	[ "$(check "$W/preflight.json" module_signatures)" = ok ]
'

test_done
