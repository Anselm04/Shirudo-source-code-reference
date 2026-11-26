#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Rebuilds testing/fixtures/keepalive/quotes.tsv, or the file named first,
# by quoting each node body under the libtpms simulator: one TPM state
# for node A and another for node B, under the directory named second or
# a fresh one, so the two nodes have different attestation keys.

set -eu

HELPER=$(cd "$(dirname "$0")" && pwd)
FIXTURES=$HELPER/../fixtures/keepalive
OUT=${1:-$FIXTURES/quotes.tsv}
STATE=${2:-}
BODIES="node-a-1.0.0 node-a-1.1.0 node-b-1.0.0 node-b-1.1.0"

for tool in "$HELPER/tpmsim-cmd" "$HELPER/test-keepalive-quote"; do
	if [ ! -x "$tool" ]; then
		echo "$tool is not built: make -C testing test-helpers" \
			"(needs libtpms)" >&2
		exit 1
	fi
done

FRESH=
if [ -z "$STATE" ]; then
	STATE=$(mktemp -d)
	FRESH=$STATE
fi
ROWS=$(mktemp "$OUT.XXXXXX")
cleanup() {
	rm -f "$ROWS"
	[ -z "$FRESH" ] || rm -rf "$FRESH"
}
trap cleanup EXIT

for body in $BODIES; do
	node=${body#node-}
	node=${node%%-*}
	mkdir -p "$STATE/node-$node"
	SHIRUDO_TPM_TCTI="cmd:exec $HELPER/tpmsim-cmd $STATE/node-$node" \
		"$HELPER/test-keepalive-quote" "$FIXTURES/$body.json" >>"$ROWS"
done
mv "$ROWS" "$OUT"
