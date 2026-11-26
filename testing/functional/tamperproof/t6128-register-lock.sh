#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6128 -- the register and the eventlog advance together only while one
# process at a time extends and appends, and the lock that serialises
# whole commands is not taken by init, which adopts the initrd's record
# while a command may append. A measuring command must hold the lock
# from its extend to its append: with the lock held elsewhere a load
# waits, and completes with a log that replays to the register. The lock
# is the root of the private bpffs, the same inode in a mount namespace
# of root's own, where a lock file beside the log could be covered with
# another labeled inode. Root may hold the lock and so delay a command,
# but cannot remove or cover it.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v flock >/dev/null 2>&1 || test_skip_all "no flock"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-lifecycle
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME"
LOCK=/run/shirudo/bpffs
[ -s "$LOAD" ] && [ -s "$UNLOAD" ] || test_skip_all "missing lifecycle fixture"
[ ! -e "$PIN" ] || test_skip_all "$NAME is loaded"

cleanup() {
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

matches() {
	"$SHIRUDO_BIN" status --json 2>/dev/null |
		python3 -c "import json,sys; sys.exit(0 if json.load(sys.stdin)[\"tpm\"][\"chain_matches_eventlog\"] else 1)"
}

lines() {
	wc -l </var/lib/shirudo/eventlog
}

test_expect_success 'root can neither remove nor cover the register lock' '
	! rmdir "$LOCK" 2>/dev/null &&
	! unshare -m mount -t tmpfs tmpfs "$LOCK" 2>/dev/null &&
	[ -e "$LOCK/identity" ]
'

test_expect_success 'a load waits while the register lock is held and then measures' '
	before=$(lines) &&
	{ flock "$LOCK" sleep 4 & holder=$!; } &&
	sleep 1 &&
	{ "$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &
	  loader=$!; } &&
	sleep 2 &&
	[ "$(lines)" = "$before" ] &&
	wait "$holder" && wait "$loader" &&
	[ "$(lines)" -gt "$before" ] &&
	[ -e "$PIN/link" ] &&
	matches
'

test_expect_success 'the unload after it leaves the register and the log in step' '
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 &&
	[ ! -e "$PIN" ] &&
	matches
'

test_expect_success 'a load in a mount namespace of root'"'"'s own waits for the same lock' '
	before=$(lines) &&
	{ flock "$LOCK" sleep 4 & holder=$!; } &&
	sleep 1 &&
	{ unshare -m "$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck \
		>/dev/null 2>&1 & loader=$!; } &&
	sleep 2 &&
	[ "$(lines)" = "$before" ] &&
	wait "$holder" && wait "$loader" &&
	[ "$(lines)" -gt "$before" ] &&
	[ -e "$PIN/link" ] &&
	matches
'

test_done
