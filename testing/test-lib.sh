# SPDX-License-Identifier: BSD-2-Clause
# shellcheck shell=sh
# Copyright (c) 2026 Authors of shirudo
#
# testing/test-lib.sh -- minimal TAP-style test harness, whiteroom of the
# subset shirudo uses. Sourced by each tNNNN-*.sh test.
#
# Public API (stable):
#   test_expect_success "<title>" "<body>"
#   test_skip_all "<reason>"
#   test_done

set -eu

: "${TAP_COUNT:=0}"
: "${TAP_FAILED:=0}"
: "${SHIRUDO_TEST_FAILURES_FILE:=}"

# Skip the whole script (TAP "1..0 # SKIP"). For tests whose
# prerequisites (root, kernel feature, opt-in env) are absent: a clean
# pass for the runner, never a failure.
test_skip_all() {
	printf '1..0 # SKIP %s\n' "$*"
	exit 0
}

# A failing body's stderr is replayed as TAP diagnostics ("# " lines),
# so a sanitizer report or an assertion message survives the harness.
test_expect_success() {
	local title="$1" body="$2" log
	TAP_COUNT=$((TAP_COUNT + 1))
	log=$(mktemp 2>/dev/null) || log=/dev/null
	if (eval "$body") >/dev/null 2>"$log"; then
		printf 'ok %d - %s\n' "$TAP_COUNT" "$title"
	else
		printf 'not ok %d - %s\n' "$TAP_COUNT" "$title"
		if [ -s "$log" ]; then
			sed 's/^/# /' "$log"
		fi
		if [ -n "$SHIRUDO_TEST_FAILURES_FILE" ]; then
			printf 'test\t%s\t%s\n' "$0" "$title" \
				>>"$SHIRUDO_TEST_FAILURES_FILE" 2>/dev/null || :
		fi
		TAP_FAILED=$((TAP_FAILED + 1))
	fi
	if [ "$log" != /dev/null ]; then
		rm -f "$log"
	fi
}

test_done() {
	printf '1..%d\n' "$TAP_COUNT"
	if [ "$TAP_FAILED" -gt 0 ]; then
		exit 1
	fi
	exit 0
}
