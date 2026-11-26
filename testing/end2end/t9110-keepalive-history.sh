#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t9110 -- the keepalive backend keeps each node's history over a tree of
# segments. The operator continues t9109's tree in segments of 2
# operations up to seq 11, past the window of 7 operations the test VM
# lowers the keepalive to. The ingest job loads every segment through bpm
# tree show --walk. The fresh edge node reports from the start, so its
# base_root is verified against node_ops, and xfs-fix, added at seq 3 below
# its window, still shields it. Node B first reports at seq 11: a gap,
# and still healthy.
#
# end2end/host.sh runs it on the host after t9109, as root, against the
# same two nodes and backend.

cd "$(dirname "$0")/.."
. ./test-lib.sh

REPO=$(cd .. && pwd)
E2E=${E2E:-$REPO/build/test-vm/end2end}
FIX=$PWD/fixtures/pipeline
S=$REPO/shirudo
CHECKS=$PWD/end2end/pipeline_checks.py
REGISTRY=${REGISTRY:-127.0.0.1:15443}
STACK_NAME=${STACK_NAME:-shirudo-end2end}
TREE=oci://$REGISTRY/shirudo/pipeline-tree
TREE_ID=pipeline
RUNTIME=/usr/local/bin/shirudo-runtime
STATE=/var/lib/shirudo/bpm/upatch-tree
CLICKHOUSE_CLIENT="docker exec -i $STACK_NAME-backend-clickhouse clickhouse-client"
export CLICKHOUSE_CLIENT
# KEEPALIVE_WINDOW_OPS of the test VM bundle's target.
WINDOW=7

[ -n "${END2END_BACKEND-}" ] && [ -n "${END2END_KEYS-}" ] ||
	test_skip_all "end2end/host.sh runs it after t9109, with a keepalive backend"
BACKEND=$END2END_BACKEND
KEYS=$END2END_KEYS
command -v docker >/dev/null 2>&1 || test_skip_all "no docker"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
[ -s "$E2E/ca.pem" ] || test_skip_all "no registry and collector CA in $E2E"
. ./vm/stack-lib.sh
. ./end2end/node-lib.sh
. ./end2end/pipeline-lib.sh
node_wait edge 0 && node_wait b 0 ||
	test_skip_all "the fresh edge node and node B are not up"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# Append hist-pad to the tree, as an add or with $1 as --op, in segments
# of 2 operations.
append() {
	"$S" bpm tree append "$W/pkg/hist-pad-1.0.0.bee" "$TREE" \
		--keys-dir "$KEYS" --tree-id pipeline --segment-ops 2 \
		${1:+--op "$1"} >&2
}

ingest() {
	"$BACKEND/jobs/tree-ingest" --shirudo "$S" --cert "$KEYS/cert.der" \
		"$TREE" >&2
}

test_expect_success 'both nodes are where t9109 left them, at seq 3 of 3' '
	for n in edge b; do
		node_view "$n" &&
		test "$(view "$n" last_seq) $(view "$n" head_seq)" = "3 3" &&
		test "$(view "$n" segment_base_seq)" = 0 &&
		on "$n" "[ ! -e $STATE/pending.json ]" || exit 1
	done &&
	"$S" bpm tree show "$TREE" --cert "$KEYS/cert.der" --walk >"$W/walk-3" &&
	python3 "$CHECKS" segments "$W/walk-3" | cut -f 1-3 >"$W/segments-3" &&
	test "$(cat "$W/segments-3")" = "$(printf "0\t3\t3")"
'

test_expect_success 'the backend starts empty, with the window lowered to 7' '
	ch "DROP DATABASE IF EXISTS shirudo SYNC" &&
	ch "DROP DATABASE IF EXISTS otel SYNC" &&
	stack_backend_schema "$BACKEND" &&
	ch "INSERT INTO shirudo.settings (stale_seconds, stuck_seconds, window)
		VALUES (600, 3600, $WINDOW)" &&
	test "$(ch "SELECT stale_seconds, stuck_seconds, window
		FROM shirudo.settings FINAL")" = "$(printf "600\t3600\t%s" "$WINDOW")" &&
	version=$(on edge "$RUNTIME version --version-id") &&
	test "$version" = "$(on b "$RUNTIME version --version-id")" &&
	ch "INSERT INTO shirudo.expected_builds (version_id, note)
		VALUES ('\''$version'\'', '\''t9110'\'')" &&
	test "$(ch "SELECT count() FROM shirudo.keepalive")" = 0 &&
	test "$(ch "SELECT count() FROM shirudo.node_ops")" = 0
'

# hist-pad selects no label, so that both nodes apply it, and stands for
# the operations a tree gathers after a fix.
test_expect_success 'the operator builds hist-pad 1.0.0' '
	mkdir -p "$W/pkg/hist-pad" &&
	sed "s/BPF_PROG(xfs_fix)/BPF_PROG(hist_pad)/" \
		"$FIX/xfs-fix/xfs-fix.bpf.c" >"$W/pkg/hist-pad/hist-pad.bpf.c" &&
	cat >"$W/pkg/hist-pad/Beefile" <<-\EOF &&
	[package]
	name = "hist-pad"
	description = "An operation of the history end-to-end test"
	license = "GPL-2.0 OR BSD-2-Clause"
	authors = ["Authors of shirudo"]

	[[upatches]]
	source = "hist-pad.bpf.c"

	[upatches.tree]
	id = "hist-pad"
	EOF
	ln -s "$REPO/vendor" "$W/pkg/hist-pad/vendor" &&
	ln -s "$REPO/bpf" "$W/pkg/hist-pad/bpf" &&
	(cd "$W/pkg" && "$S" bpm build hist-pad --version 1.0.0 \
		--keys-dir "$KEYS") >&2
'

test_expect_success 'seq 4 and 5 seal the first segment; the edge node reports' '
	append && append delete &&
	ingest &&
	unit_ok edge shirudo-bpm-tree-sync.service &&
	node_view edge &&
	test "$(view edge last_seq) $(view edge segment_base_seq)" = "5 3" &&
	unit_ok edge shirudo-keepalive.service &&
	ch_wait "SELECT count() FROM shirudo.keepalive FINAL" 1 &&
	ak_record edge &&
	test "$(view edge base_seq)" = 0 &&
	latest_cmp edge &&
	refresh node_ops_mv &&
	history_cmp edge 0
'

# Node B syncs without reporting: a walk of 2 operations back from seq 3,
# within the 4 a running node of the test VM walks.
test_expect_success 'seq 6 and 7: node B walks back a segment, unseen by the backend' '
	append && append delete &&
	ingest &&
	unit_ok edge shirudo-bpm-tree-sync.service &&
	unit_ok b shirudo-bpm-tree-sync.service &&
	node_view edge && node_view b &&
	test "$(view b last_seq) $(view b segment_base_seq)" = "7 5" &&
	test "$(view b history_root)" = "$(view edge history_root)" &&
	unit_ok edge shirudo-keepalive.service &&
	ch_wait "SELECT count() FROM shirudo.keepalive FINAL" 2 &&
	test "$(view edge base_seq)" = 0 &&
	latest_cmp edge &&
	refresh node_ops_mv &&
	history_cmp edge 0 &&
	test "$(ch "SELECT uniqExact(ak_name) FROM shirudo.keepalive")" = 1
'

test_expect_success 'seq 8 to 11: both nodes report a window past seq 0' '
	append && append delete && append && append delete &&
	ingest &&
	for n in edge b; do
		unit_ok "$n" shirudo-bpm-tree-sync.service &&
		node_view "$n" &&
		test "$(view "$n" last_seq) $(view "$n" segment_base_seq)" = "11 9" &&
		test "$(view "$n" base_seq)" = 4 || exit 1
	done &&
	unit_ok edge shirudo-keepalive.service &&
	unit_ok b shirudo-keepalive.service &&
	ch_wait "SELECT count() FROM shirudo.keepalive FINAL" 4 &&
	ak_record b &&
	test "$(ak edge)" != "$(ak b)" &&
	test "$(ch "SELECT count() FROM shirudo.rejected")" = 0 &&
	for n in edge b; do
		latest_cmp "$n" &&
		on "$n" "$RUNTIME status --keepalive" >"$W/keepalive-$n" &&
		python3 - "$W/keepalive-$n" "$W/view-$n" <<-\PY || exit 1
		import json, sys
		body, view = (json.load(open(p)) for p in sys.argv[1:3])
		for key in "base_seq", "base_root", "mask", "last_seq", "projection_root":
		    assert body[key] == view[key], (key, body[key], view[key])
		PY
	done
'

test_expect_success 'bpm tree show --walk loads every segment into the backend' '
	"$S" bpm tree show "$TREE" --cert "$KEYS/cert.der" --walk >"$W/walk" &&
	python3 "$CHECKS" segments "$W/walk" >"$W/segments" &&
	cut -f 1-3 "$W/segments" >"$W/bounds" &&
	printf "%s\t%s\t%s\n" 0 3 3 3 5 5 5 7 7 7 9 9 9 11 11 >"$W/bounds.expected" &&
	diff -u "$W/bounds.expected" "$W/bounds" >&2 &&
	cut -f 4 "$W/segments" | head -n 4 >"$W/sealed" &&
	python3 "$CHECKS" tags "$REGISTRY" "$E2E/ca.pem" shirudo/pipeline-tree 4 \
		>"$W/tags" &&
	diff -u "$W/sealed" "$W/tags" >&2 &&
	sed "s/\t-\t/\t\t/" "$W/segments" >"$W/pubs" &&
	ch_cmp "SELECT segment_base_seq, head_seq, generation, manifest_digest,
		segment_manifest_digest, history_root
		FROM shirudo.tree_pubs FINAL WHERE tree_id = '\''pipeline'\''
		ORDER BY generation" "$W/pubs" &&
	python3 "$CHECKS" operations "$W/walk" >"$W/ops" &&
	test "$(wc -l <"$W/ops")" = 11 &&
	ch_cmp "SELECT seq, op, id, operation_digest FROM shirudo.tree_ops FINAL
		WHERE tree_id = '\''pipeline'\'' ORDER BY seq" "$W/ops" &&
	cut -f 4 "$W/ops" >"$W/digests" &&
	test "$(python3 "$CHECKS" roots $(cat "$W/digests") | cut -d " " -f 2)" = \
		"$(view edge history_root)"
'

test_expect_success 'node_ops holds the edge node from seq 1 and node B from a gap at 4' '
	refresh node_ops_mv &&
	history_cmp edge 0 &&
	history_cmp b 4 &&
	printf "hist-pad\t11\tdelete\nxfs-fix\t3\tadd\n" >"$W/sets-edge" &&
	ch_cmp "SELECT id, last_seq, last_op FROM shirudo.node_sets FINAL
		WHERE ak_name = '\''$(ak edge)'\'' ORDER BY id" "$W/sets-edge"
'

test_expect_success 'base_root is verified on the edge node; node B shows a gap, healthy' '
	refresh node_status_mv &&
	printf "%s\thealthy\t0\n" "$(ak b)" "$(ak edge)" | sort >"$W/status" &&
	status_log edge >"$W/log-edge" &&
	status_log b >"$W/log-b" &&
	status_cmp "$W/status" &&
	root_edge=$(view edge projection_root | cut -c 1-8) &&
	root_b=$(view b projection_root | cut -c 1-8) &&
	grep -qx "4 chain: pass, root $root_edge" "$W/log-edge" &&
	grep -qx "5 head: pass, seq 11 of 11, generation 11" "$W/log-edge" &&
	grep -qx "6 set: pass, 1 loaded" "$W/log-edge" &&
	grep -qx "4 chain: pass, root $root_b, base unverified (gap)" "$W/log-b" &&
	grep -qx "5 head: pass, seq 11 of 11, generation 11" "$W/log-b" &&
	grep -qx "6 set: set unverified (gap), 0 loaded" "$W/log-b"
'

# xfs-fix 1.1.0 was added at seq 3 with fixes EXAMPLE-0101, below the
# window of seq 5 to 11: only the history says what each node did there.
test_expect_success 'the shield below the window still reads shielded on the edge node' '
	stack_backend_client --query "INSERT INTO shirudo.kernel_vulns FORMAT JSONEachRow" \
		<"$FIX/kernel-vulns.json" &&
	refresh node_vulns_mv &&
	cat >"$W/vulns" <<-EOF &&
	b	EXAMPLE-0101	unknown	xfs-fix	3	add	fixes
	edge	EXAMPLE-0101	shielded	xfs-fix	3	add	fixes
	EOF
	ch_cmp "SELECT if(ak_name = '\''$(ak edge)'\'', '\''edge'\'', '\''b'\'') AS node,
		vuln_id, exposure, upatch_id, applied_seq, applied_op, shield_link
		FROM shirudo.node_vulns WHERE source = '\''kernel'\''
		ORDER BY node, vuln_id" "$W/vulns"
'

test_done
