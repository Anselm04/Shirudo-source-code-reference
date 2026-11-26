#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t4002 -- the record an init run from the initrd leaves under /run:
# readers see it as this boot's init record before the root file
# system's init adopts it, and adoption appends it to the eventlog
# exactly once.

cd "$(dirname "$0")/../.."
. ./test-lib.sh
H=helper/test-eventlog
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
export SHIRUDO_EVENTLOG_PATH="$W/eventlog"
export SHIRUDO_EVENTLOG_PENDING_PATH="$W/eventlog.pending"

test_expect_success 'no log and no pending record: no init this boot' '
	./$H boot-init | grep -qx "rc=-2"
'

test_expect_success 'a pending record is this boot'"'"'s init record' '
	./$H init pending initrd | grep -qx "rc=0" &&
	test ! -e "$SHIRUDO_EVENTLOG_PATH" &&
	./$H boot-init | grep -qx "bound_in=initrd" &&
	./$H lines | grep -qx "lines=1"
'

test_expect_success 'adoption appends it to the log and removes the pending file' '
	cp "$SHIRUDO_EVENTLOG_PENDING_PATH" "$W/saved" &&
	./$H adopt | grep -qx "pending=absent" &&
	[ "$(wc -l < "$SHIRUDO_EVENTLOG_PATH")" = 1 ] &&
	./$H boot-init | grep -qx "bound_in=initrd"
'

test_expect_success 'adopting the same record again changes nothing' '
	cp "$W/saved" "$SHIRUDO_EVENTLOG_PENDING_PATH" &&
	./$H adopt | grep -qx "pending=absent" &&
	[ "$(wc -l < "$SHIRUDO_EVENTLOG_PATH")" = 1 ] &&
	./$H adopt | grep -qx "rc=0" &&
	[ "$(wc -l < "$SHIRUDO_EVENTLOG_PATH")" = 1 ]
'

test_expect_success 'a pending record follows the log'"'"'s records of this boot' '
	./$H init pending initrd 2 | grep -qx "rc=0" &&
	./$H boot-init | grep -qx "reset_count=2" &&
	./$H lines | grep -qx "lines=2" &&
	./$H adopt | grep -qx "pending=absent" &&
	[ "$(wc -l < "$SHIRUDO_EVENTLOG_PATH")" = 2 ] &&
	./$H boot-init | grep -qx "records=2"
'

# init adopts while a command may append under the register lock: both
# adopters found the record missing and appended it twice.
test_expect_success 'adopters wait for the register lock and append the record once' '
	command -v flock >/dev/null 2>&1 || exit 0
	rm -f "$SHIRUDO_EVENTLOG_PATH" &&
	cp "$W/saved" "$SHIRUDO_EVENTLOG_PENDING_PATH" &&
	touch "$SHIRUDO_EVENTLOG_PATH.lock" &&
	{ flock "$SHIRUDO_EVENTLOG_PATH.lock" sleep 2 & holder=$!; } &&
	sleep 0.5 &&
	{ ./$H adopt >"$W/a1" & a1=$!; } &&
	{ ./$H adopt >"$W/a2" & a2=$!; } &&
	sleep 0.5 &&
	[ ! -e "$SHIRUDO_EVENTLOG_PATH" ] &&
	wait "$holder" && wait "$a1" && wait "$a2" &&
	[ "$(wc -l < "$SHIRUDO_EVENTLOG_PATH")" = 1 ] &&
	[ ! -e "$SHIRUDO_EVENTLOG_PENDING_PATH" ]
'

test_done
