#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3110 -- a second load of a loaded upatch is refused as already_loaded
# and leaves the loaded one, its pins and its serializers as they are.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
EVENTLOG=/var/lib/shirudo/eventlog
PINS=/run/shirudo/bpffs/upatches
BASIC=shirudo-test-basic
SERIAL=shirudo-test-serialized-metric

for n in $BASIC $SERIAL; do
	[ -s "$FIXTURES/$n.upatch" ] && [ -s "$FIXTURES/$n.unload.upatch" ] ||
		test_skip_all "missing fixture $n"
done

restore() {
	for n in $BASIC $SERIAL; do
		[ -d "$PINS/$n" ] || continue
		"$SHIRUDO_BIN" upatch unload "$FIXTURES/$n.unload.upatch" \
			--no-precheck >/dev/null 2>&1 || true
	done
}
trap restore EXIT HUP INT TERM

load_events() {
	grep -c "\"upatch_load\".*\"$1\"" "$EVENTLOG"
}

second_load() {
	"$SHIRUDO_BIN" upatch load "$FIXTURES/$1.upatch" --no-precheck \
		--report=- 2>/dev/null | report_field category
}

test_expect_success 'a second load of a upatch with links is refused and detaches nothing' '
	require_loaded $BASIC &&
	before=$(load_events $BASIC) &&
	[ "$(second_load $BASIC)" = already_loaded ] &&
	[ -e "$PINS/$BASIC/link" ] &&
	[ "$(load_events $BASIC)" = "$before" ]
'

test_expect_success 'a second load of a upatch without links keeps its serializer bound' '
	require_loaded $SERIAL &&
	before=$(load_events $SERIAL) &&
	[ "$(second_load $SERIAL)" = already_loaded ] &&
	[ -e "$PINS/$SERIAL/serializers/counters" ] &&
	[ "$(load_events $SERIAL)" = "$before" ] &&
	! "$SHIRUDO_BIN" upatch map $SERIAL counters 2>&1 |
		grep -q "Bad message"
'

test_done
