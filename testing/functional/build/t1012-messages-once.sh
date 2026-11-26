#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1012 -- a message goes to standard error and to syslog, and to syslog
# alone where standard error is the journal stream systemd names in
# JOURNAL_STREAM, so that the journal of a unit holds it once.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

SHIRUDO=../shirudo
W=$(mktemp -d) || exit 1
trap 'rm -rf "$W"' EXIT
MESSAGE="upatch info: $W/none.upatch: No such file or directory"

# The lines of standard error that are the message, with JOURNAL_STREAM
# set to $1 when it is not empty. The command fails, as it must.
copies() {
	: >"$W/err"
	if [ -n "$1" ]; then
		JOURNAL_STREAM=$1 $SHIRUDO upatch info "$W/none.upatch" \
			2>>"$W/err" || true
	else
		$SHIRUDO upatch info "$W/none.upatch" 2>>"$W/err" || true
	fi
	grep -cFx "$MESSAGE" "$W/err" || true
}

test_expect_success 'a message goes to standard error' '
	[ "$(copies "")" = 1 ]
'

# Without /dev/log syslog drops the message, and the copy stays.
if [ -e /dev/log ]; then
	test_expect_success 'a standard error that is the journal stream gets no copy' '
		: >"$W/err" &&
		[ "$(copies "$(stat -c %d:%i "$W/err")")" = 0 ]
	'
else
	test_expect_success 'without /dev/log the journal stream keeps its copy' '
		: >"$W/err" &&
		[ "$(copies "$(stat -c %d:%i "$W/err")")" = 1 ]
	'
fi

test_expect_success 'another stream in JOURNAL_STREAM leaves standard error its copy' '
	[ "$(copies 1:2)" = 1 ] &&
	[ "$(copies garbage)" = 1 ]
'

test_done
