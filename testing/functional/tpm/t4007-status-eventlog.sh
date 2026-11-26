#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t4007 -- status --include-eventlog lists the eventlog line by line: a
# NUL in the log hides no record behind it, the line that holds it is
# listed as one that does not parse, an append that did not finish is no
# entry, and the entries counted are the entries listed. The walk read
# the log as one string, so that the list ended at a NUL without a word.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

SHIRUDO=${SHIRUDO:-../shirudo}
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
export SHIRUDO_EVENTLOG_PATH="$W/eventlog"

record() {
	printf '{"schema":1,"ts":"2026-11-20T00:00:0%sZ","type":"%s","digest":"%064d","upatch":{"name":"%s","payload_sha256":"%064d"}}' \
		"$1" "$2" "$1" "$3" "$1"
}

# How many events of the JSON report have type $1.
events() {
	"$SHIRUDO" status --json --include-eventlog 2>/dev/null |
		grep -o "\"type\":\"$1\"" | wc -l
}

entries() {
	"$SHIRUDO" status --json --include-eventlog 2>/dev/null |
		grep -o '"entries":[0-9]*' | cut -d: -f2
}

test_expect_success 'every record of the log is listed' '
	{ record 1 upatch_load one; echo; record 2 upatch_unload one; echo; } \
		>"$SHIRUDO_EVENTLOG_PATH" &&
	[ "$(entries)" = 2 ] &&
	[ "$(events upatch_load)" = 1 ] &&
	[ "$(events upatch_unload)" = 1 ] &&
	"$SHIRUDO" status --include-eventlog >"$W/table" 2>/dev/null &&
	grep -q "upatch_unload .* one payload=" "$W/table"
'

test_expect_success 'a NUL in the log hides no record behind it' '
	{ record 1 upatch_load one; echo; printf "\000"; record 2 upatch_load two
	  echo; record 3 upatch_unload one; echo; } >"$SHIRUDO_EVENTLOG_PATH" &&
	[ "$(entries)" = 3 ] &&
	[ "$(events upatch_load)" = 1 ] &&
	[ "$(events unparseable)" = 1 ] &&
	[ "$(events upatch_unload)" = 1 ] &&
	"$SHIRUDO" status --include-eventlog >"$W/table" 2>/dev/null &&
	grep -q "unparseable" "$W/table" &&
	grep -q "upatch_unload .* one payload=" "$W/table"
'

test_expect_success 'an append that did not finish is no entry' '
	{ record 1 upatch_load one; echo; record 2 upatch_unload one; } \
		>"$SHIRUDO_EVENTLOG_PATH" &&
	[ "$(entries)" = 1 ] &&
	[ "$(events upatch_load)" = 1 ] &&
	[ "$(events upatch_unload)" = 0 ] &&
	"$SHIRUDO" status --include-eventlog >"$W/table" 2>/dev/null &&
	! grep -q "upatch_unload" "$W/table"
'

test_done
