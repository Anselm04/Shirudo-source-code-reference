#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t4006 -- the quotes of testing/fixtures/keepalive/quotes.tsv: each row
# covers its body file as it is now, verifies under shirudo-quote-check
# without a TPM, node A and node B each sign with a key of their own, and
# the capture script rebuilds a file that verifies as well.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

QUOTE_CHECK=${QUOTE_CHECK:-../tools/quote-check/shirudo-quote-check}
[ -x "$QUOTE_CHECK" ] || test_skip_all "shirudo-quote-check is not built"
FIXTURES=fixtures/keepalive
QUOTES=$FIXTURES/quotes.tsv
BODIES="node-a-1.0.0.json node-a-1.1.0.json node-b-1.0.0.json node-b-1.1.0.json"
W=$(mktemp -d) || exit 1
trap 'rm -rf "$W"' EXIT

# Fails when a row of quotes file $1 names a body that is not in
# directory $2 or a body_sha256 that is not SHA-256 of that file.
rows_match_bodies() {
	[ "$(cut -f1 "$1" | tr '\n' ' ')" = "$BODIES " ] || return 1
	while IFS='	' read -r name _ _ _ hash; do
		[ "$(sha256sum <"$2/$name" | cut -d' ' -f1)" = "$hash" ] ||
			return 1
	done <"$1"
}

# Checks quotes file $1 with the checker, its lines in $2: every row
# passes, node A's two rows under one key and node B's under another.
check_quotes() {
	cut -f2- "$1" | "$QUOTE_CHECK" >"$2" &&
	[ "$(wc -l <"$2")" -eq 4 ] &&
	! grep -v '^{"ok":1,' "$2" &&
	sed -n 's/.*"ak_name":"\([0-9a-f]*\)".*/\1/p' "$2" >"$2.names" &&
	[ "$(sed -n 1p "$2.names")" = "$(sed -n 2p "$2.names")" ] &&
	[ "$(sed -n 3p "$2.names")" = "$(sed -n 4p "$2.names")" ] &&
	[ "$(sed -n 1p "$2.names")" != "$(sed -n 3p "$2.names")" ] &&
	[ "$(sort -u "$2.names" | wc -l)" -eq 2 ]
}

test_expect_success 'every row covers its body file as it is now' '
	rows_match_bodies "$QUOTES" "$FIXTURES"
'

test_expect_success 'a body altered by one byte fails the staleness check' '
	mkdir "$W/stale" &&
	for b in $BODIES; do cp "$FIXTURES/$b" "$W/stale/" || exit 1; done &&
	sed -i "s/\"verdict\":\"ok\"/\"verdict\":\"oK\"/" \
		"$W/stale/node-b-1.1.0.json" &&
	! cmp -s "$FIXTURES/node-b-1.1.0.json" "$W/stale/node-b-1.1.0.json" &&
	! rows_match_bodies "$QUOTES" "$W/stale"
'

test_expect_success 'every row verifies, with one key per node' '
	check_quotes "$QUOTES" "$W/checked"
'

test_expect_success 'a body altered by one byte does not match its quote' '
	sha=$(sed "s/\"verdict\":\"ok\"/\"verdict\":\"oK\"/" \
		"$FIXTURES/node-a-1.0.0.json" | sha256sum | cut -d" " -f1) &&
	[ "$sha" != "$(sed -n 1p "$QUOTES" | cut -f5)" ] &&
	sed -n 1p "$QUOTES" | cut -f2-4 >"$W/altered.row" &&
	sed -i "s/\$/	$sha/" "$W/altered.row" &&
	"$QUOTE_CHECK" <"$W/altered.row" >"$W/altered.out" &&
	[ "$(cat "$W/altered.out")" = "{\"ok\":0,\"reason\":\"body_mismatch\"}" ]
'

if [ -x helper/tpmsim-cmd ] && [ -x helper/test-keepalive-quote ]; then
	test_expect_success 'the capture script rebuilds quotes that verify' '
		helper/capture-keepalive-quotes.sh "$W/recaptured.tsv" &&
		rows_match_bodies "$W/recaptured.tsv" "$FIXTURES" &&
		check_quotes "$W/recaptured.tsv" "$W/rechecked"
	'
fi

test_done
