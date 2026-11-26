#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6122 -- a load whose archive copy fails is undone. The archive is
# written after the programs are attached and pinned, and a root that
# fills the file system before the archive copy got a signed upatch
# running with no archive and no register event: unmeasured, and not
# restored at the next boot. The load must report the persist failure
# with its pins gone.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v fallocate >/dev/null 2>&1 || test_skip_all "no fallocate"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-lifecycle
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME"
FILL=/var/tmp/t6122-fill
[ -s "$LOAD" ] && [ -s "$UNLOAD" ] || test_skip_all "missing lifecycle fixture"
[ ! -e "$PIN" ] || test_skip_all "$NAME is loaded"
[ "$(stat -c %d /var/tmp)" = "$(stat -c %d /var/lib/shirudo)" ] ||
	test_skip_all "/var/tmp and /var/lib/shirudo are on different file systems"

# Under the library's errexit a failing step would end the cleanup.
cleanup() {
	rm -f "$FILL".* 2>/dev/null || true
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

# Leave room for half of the archive copy, not for all of it: reserve
# that much, fill the rest to the last block fallocate takes, then give
# the reservation back.
fill() {
	size=$(stat -c %s "$LOAD")
	fallocate -l $((size / 2)) "$FILL.keep" || return 1
	n=0
	chunk=$((64 * 1024 * 1024))
	while [ "$chunk" -ge 4096 ]; do
		if fallocate -l "$chunk" "$FILL.$n" 2>/dev/null; then
			n=$((n + 1))
		else
			chunk=$((chunk / 2))
		fi
	done
	rm -f "$FILL.keep"
}

test_expect_success 'a load whose archive copy fails is undone, pins included' '
	phase= &&
	{ fill && phase=$("$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck \
		--report=- 2>/dev/null | report_field phase); } ; rc=$? ;
	rm -f "$FILL".* &&
	[ "$rc" = 0 ] &&
	[ "$phase" = persist ] &&
	[ ! -e "$PIN" ] &&
	[ ! -e "/var/lib/shirudo/upatches/$NAME.upatch" ]
'

test_expect_success 'the same load succeeds with room again' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	[ -e "$PIN/link" ] &&
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 &&
	[ ! -e "$PIN" ]
'

test_done
