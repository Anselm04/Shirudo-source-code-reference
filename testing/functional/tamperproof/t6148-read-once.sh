#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6148 -- a load and an unload read the operator's file once, into
# memory: neither leaves a copy in sealed state under a name another
# command could take, and the archive holds the bytes that were loaded.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
FIXTURES=$SHIRUDO_TEST_FIXTURES_DIR
NAME=shirudo-test-basic
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PINDIR="/run/shirudo/bpffs/upatches/$NAME"
ARCHIVE="/var/lib/shirudo/upatches/$NAME.upatch"
W=$(mktemp -d)
cleanup() {
	[ ! -e "$PINDIR" ] ||
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" >/dev/null 2>&1 || :
	rm -rf "$W"
}
trap cleanup EXIT
[ -s "$LOAD" ] && [ -s "$UNLOAD" ] || test_skip_all "missing fixture $NAME"
[ ! -e "$PINDIR" ] || "$SHIRUDO_BIN" upatch unload "$UNLOAD" >/dev/null 2>&1
[ ! -e "$PINDIR" ] || test_skip_all "$NAME cannot be unloaded"
# What sealed state holds apart from the eventlog, its lock and archives.
state() {
	find /var/lib/shirudo -xdev ! -path /var/lib/shirudo/eventlog \
		! -path /var/lib/shirudo/eventlog.lock \
		! -path '/var/lib/shirudo/upatches*' | sort
}
state >"$W/before"

test_expect_success 'a load archives the bytes it read and stages nothing' '
	"$SHIRUDO_BIN" upatch load "$LOAD" >/dev/null 2>&1 &&
	[ -e "$PINDIR/link" ] &&
	cmp -s "$LOAD" "$ARCHIVE" &&
	state >"$W/after" &&
	cmp -s "$W/before" "$W/after"
'
test_expect_success 'an unload stages nothing either' '
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" >/dev/null 2>&1 &&
	[ ! -e "$PINDIR" ] &&
	[ ! -e "$ARCHIVE" ] &&
	state >"$W/after" &&
	cmp -s "$W/before" "$W/after"
'
test_done
