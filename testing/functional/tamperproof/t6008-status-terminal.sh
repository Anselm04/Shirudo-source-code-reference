#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6008 -- status prints the host name as text: sethostname() takes any
# bytes from root, and a name that held an escape sequence reached the
# terminal as one, where it can erase the line it stands on and write
# another in its place. Each control byte is shown as "?" instead, and
# the JSON report escapes it.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

SHIRUDO=${SHIRUDO:-../shirudo}
for c in python3 unshare; do
	command -v $c >/dev/null 2>&1 || test_skip_all "no $c"
done
if unshare --uts true 2>/dev/null; then
	UNSHARE="unshare --uts"
elif unshare --user --map-root-user --uts true 2>/dev/null; then
	UNSHARE="unshare --user --map-root-user --uts"
else
	test_skip_all "cannot unshare a UTS namespace"
fi
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
export SHIRUDO_EVENTLOG_PATH="$W/eventlog"

# status under the host name "node", the erase-line sequence, a carriage
# return and a line of the report's own making.
status_as_spoofed_host() {
	$UNSHARE python3 -c '
import os, socket, sys
socket.sethostname(b"node\x1b[2K\rStatus:                ok")
os.execv(sys.argv[1], sys.argv[1:])' "$SHIRUDO" status "$@"
}

test_expect_success 'no control byte of the host name reaches the terminal' '
	status_as_spoofed_host >"$W/out" 2>/dev/null
	head -n 1 "$W/out" >"$W/host" &&
	! LC_ALL=C grep -q "[[:cntrl:]]" "$W/host" &&
	grep -qx "Host:  *node?\[2K?Status:  *ok" "$W/host"
'

test_expect_success 'the JSON report escapes the same bytes' '
	status_as_spoofed_host --json >"$W/json" 2>/dev/null
	! LC_ALL=C grep -q "$(printf "\033")" "$W/json" &&
	grep -q "\"host\":\"node\\\\u001b\[2K\\\\rStatus:  *ok\"" "$W/json"
'

test_done
