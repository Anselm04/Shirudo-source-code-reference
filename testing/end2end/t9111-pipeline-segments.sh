#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t9111 -- a backward walk on real data. The operator appends five
# operations to a new tree in segments of 2: xfs-fix 1.0.0 for role=edge,
# net-guard for every node, the delete of xfs-fix 1.0.0, xfs-fix 1.1.0 and
# the delete of net-guard. Node B (role=core) syncs once inside the first
# segment. After seq 4 the edge node, which has followed no tree, and
# node B both walk back to the sealed segment by its digest and apply
# forwards; after seq 5 neither walks. The registry's access log shows
# each fetch, and the backend sees one tree of three segments.
#
# end2end/host.sh runs it on the host after t9110, as root, against a
# fresh edge node, a fresh node B and a registry that holds no tree.

cd "$(dirname "$0")/.."
. ./test-lib.sh

REPO=$(cd .. && pwd)
E2E=${E2E:-$REPO/build/test-vm/end2end}
FIX=$PWD/fixtures/pipeline
S=$REPO/shirudo
CHECKS=$PWD/end2end/pipeline_checks.py
REGISTRY=${REGISTRY:-127.0.0.1:15443}
STACK_NAME=${STACK_NAME:-shirudo-end2end}
REPOSITORY=shirudo/pipeline-tree
TREE=oci://$REGISTRY/$REPOSITORY
TREE_ID=segments
RUNTIME=/usr/local/bin/shirudo-runtime
STATE=/var/lib/shirudo/bpm/upatch-tree
CLICKHOUSE_CLIENT="docker exec -i $STACK_NAME-backend-clickhouse clickhouse-client"
export CLICKHOUSE_CLIENT
# KEEPALIVE_WINDOW_OPS of the test VM bundle's target. The tree's five
# operations fit in it, so every keepalive's window starts at seq 0.
WINDOW=7

[ -n "${END2END_BACKEND-}" ] && [ -n "${END2END_KEYS-}" ] ||
	test_skip_all "end2end/host.sh runs it after t9110, with a keepalive backend"
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

# Append the package $1, a path under $W/pkg without .bee, to the tree in
# segments of 2 operations, as an add or with $2 as --op.
append() {
	"$S" bpm tree append "$W/pkg/$1.bee" "$TREE" --keys-dir "$KEYS" \
		--tree-id "$TREE_ID" --segment-ops 2 ${2:+--op "$2"} >&2
}

# Write the walk of the tree back from its stable tag to $W/walk.
walk() {
	"$S" bpm tree show "$TREE" --cert "$KEYS/cert.der" --walk >"$W/walk"
}

ingest() {
	"$BACKEND/jobs/tree-ingest" --shirudo "$S" --cert "$KEYS/cert.der" \
		"$TREE" >&2
}

# The payload_sha256 of the upatch $2 in the package of release $1.
payload() {
	tar -xzf "$W/pkg/$1/$2-$1.bee" -C "$W/pkg/$1" &&
	"$S" upatch info --json "$W/pkg/$1/$2-$1/upatches/$2.upatch" |
		python3 -c 'import json, sys; print(json.load(sys.stdin)["payload_sha256"])'
}

# Sync node $1 in step $2 and print the manifests it fetched from the
# tree's repository; $W/requests-$1 holds all it asked of that
# repository. Marks in the registry's access log bound the sync.
sync_node() {
	registry_mark "$2-$1" &&
	unit_ok "$1" shirudo-bpm-tree-sync.service &&
	registry_mark "$2-$1-done" &&
	requests "$2-$1" "$2-$1-done" "$REPOSITORY" >"$W/requests-$1" &&
	sed -n "s|^GET manifests/||p" "$W/requests-$1"
}

# Check node $1 with labels $2 at seq $3 of the walk: its records against
# the published operations, its mask $4, the seq of its tree_op events
# $5 and its loaded upatches, file $6.
node_check() {
	node_view "$1" &&
	test "$(view "$1" last_seq) $(view "$1" head_seq)" = "$3 $3" &&
	on "$1" "[ ! -e $STATE/pending.json ]" &&
	test "$(python3 "$CHECKS" expect "$W/view-$1" "$W/walk" "$2")" = "$4" &&
	test "$(view "$1" mask)" = "$4" &&
	on "$1" "$RUNTIME attest --nonce=$(openssl rand -hex 16)" \
		>"$W/evidence-$1" &&
	test "$(python3 "$CHECKS" tree-events "$W/evidence-$1")" = "$5" &&
	on "$1" "$RUNTIME upatch list --json" >"$W/upatches-$1" &&
	python3 "$CHECKS" loaded "$W/upatches-$1" >"$W/loaded-$1" &&
	diff -u "$6" "$W/loaded-$1" >&2
}

# Send a keepalive from each node and wait for the backend to hold $1
# records in all.
report() {
	unit_ok edge shirudo-keepalive.service &&
	unit_ok b shirudo-keepalive.service &&
	ch_wait "SELECT count() FROM shirudo.keepalive FINAL" "$1" &&
	test "$(ch "SELECT count() FROM shirudo.rejected")" = 0
}

test_expect_success 'both nodes have followed no tree, and the registry holds none' '
	for n in edge b; do
		on "$n" "[ ! -e $STATE/state.json ] && [ ! -e $STATE/outcomes ]" &&
		on "$n" "$RUNTIME upatch list --json" >"$W/upatches-$n" &&
		test -z "$(python3 "$CHECKS" loaded "$W/upatches-$n")" || exit 1
	done &&
	test "$(curl -s -o /dev/null -w "%{http_code}" --cacert "$E2E/ca.pem" \
		"https://$REGISTRY/v2/$REPOSITORY/manifests/stable")" = 404
'

test_expect_success 'the backend starts empty, with the window lowered to 7' '
	ch "DROP DATABASE IF EXISTS shirudo SYNC" &&
	ch "DROP DATABASE IF EXISTS otel SYNC" &&
	stack_backend_schema "$BACKEND" &&
	ch "INSERT INTO shirudo.settings (stale_seconds, stuck_seconds, window)
		VALUES (600, 3600, $WINDOW)" &&
	version=$(on edge "$RUNTIME version --version-id") &&
	test "$version" = "$(on b "$RUNTIME version --version-id")" &&
	ch "INSERT INTO shirudo.expected_builds (version_id, note)
		VALUES ('\''$version'\'', '\''t9111'\'')" &&
	test "$(ch "SELECT count() FROM shirudo.keepalive")" = 0
'

test_expect_success 'both nodes trust the CA and reach the registry' '
	node_reach edge &&
	node_reach b
'

# 1.1.0 differs from 1.0.0 in its program name, so that the two payloads
# differ, as in t9109.
test_expect_success 'the operator builds xfs-fix 1.0.0 and 1.1.0, and net-guard 1.0.0' '
	for p in 1.0.0/xfs-fix 1.1.0/xfs-fix 1.0.0/net-guard; do
		mkdir -p "$W/pkg/${p%/*}" &&
		cp -R "$FIX/${p#*/}" "$W/pkg/$p" &&
		ln -s "$REPO/vendor" "$W/pkg/$p/vendor" &&
		ln -s "$REPO/bpf" "$W/pkg/$p/bpf" || exit 1
	done &&
	sed -i "s/BPF_PROG(xfs_fix)/BPF_PROG(xfs_fix_1_1)/" \
		"$W/pkg/1.1.0/xfs-fix/xfs-fix.bpf.c" &&
	for p in 1.0.0/xfs-fix 1.1.0/xfs-fix 1.0.0/net-guard; do
		(cd "$W/pkg/${p%/*}" && "$S" bpm build "${p#*/}" \
			--version "${p%/*}" --keys-dir "$KEYS") >&2 &&
		payload "${p%/*}" "${p#*/}" >"$W/payload-${p#*/}-${p%/*}" || exit 1
	done &&
	! cmp -s "$W/payload-xfs-fix-1.0.0" "$W/payload-xfs-fix-1.1.0"
'

test_expect_success 'append 1 starts segment 1; node B passes over seq 1' '
	append 1.0.0/xfs-fix-1.0.0 &&
	walk &&
	python3 "$CHECKS" segments "$W/walk" | cut -f 1-3 >"$W/bounds" &&
	test "$(cat "$W/bounds")" = "$(printf "0\t1\t1")" &&
	sync_node b step-1 >"$W/fetched" &&
	test "$(cat "$W/fetched")" = stable &&
	: >"$W/loaded" &&
	node_check b role=core 1 gA== "" "$W/loaded" &&
	test "$(view b segment_base_seq)" = 0
'

test_expect_success 'appends 2 to 4 seal segment 1 at generation 2 as segment-1' '
	append 1.0.0/net-guard-1.0.0 &&
	append 1.0.0/xfs-fix-1.0.0 delete &&
	append 1.1.0/xfs-fix-1.1.0 &&
	walk &&
	python3 "$CHECKS" segments "$W/walk" >"$W/segments-4" &&
	printf "%s\t%s\t%s\n" 0 2 2 2 4 4 >"$W/bounds.expected" &&
	cut -f 1-3 "$W/segments-4" | diff -u "$W/bounds.expected" - >&2 &&
	sed -n 1p "$W/segments-4" | cut -f 4 >"$W/segment-1" &&
	python3 "$CHECKS" tags "$REGISTRY" "$E2E/ca.pem" "$REPOSITORY" 1 |
		diff -u "$W/segment-1" - >&2 &&
	sed -n 2p "$W/segments-4" | cut -f 5 | diff -u "$W/segment-1" - >&2
'

# The edge node has last_seq 0: a walk of 2 operations back from segment
# 2's base, within the 6 a joining node of the test VM walks.
test_expect_success 'the edge node walks back to segment 1 by digest and applies 1 to 4' '
	sync_node edge step-2 >"$W/fetched" &&
	test "$(sed -n 1p "$W/fetched")" = stable &&
	sed 1d "$W/fetched" | grep -qx "sha256:$(cat "$W/segment-1")" &&
	! grep -q "segment-" "$W/requests-edge" &&
	printf "net-guard %s\nxfs-fix %s\n" "$(cat "$W/payload-net-guard-1.0.0")" \
		"$(cat "$W/payload-xfs-fix-1.1.0")" >"$W/loaded" &&
	node_check edge role=edge 4 VQ== "1 2 3 4" "$W/loaded" &&
	test "$(view edge segment_base_seq)" = 2
'

# Node B is behind inside the sealed segment: a walk of 1 operation from
# its last_seq 1, within the 4 a running node of the test VM walks.
test_expect_success 'node B walks back into segment 1 from seq 1 and processes 2 to 4' '
	sync_node b step-2 >"$W/fetched" &&
	test "$(sed -n 1p "$W/fetched")" = stable &&
	sed 1d "$W/fetched" | grep -qx "sha256:$(cat "$W/segment-1")" &&
	! grep -q "segment-" "$W/requests-b" &&
	printf "net-guard %s\n" "$(cat "$W/payload-net-guard-1.0.0")" >"$W/loaded" &&
	node_check b role=core 4 mg== 2 "$W/loaded" &&
	test "$(view b segment_base_seq)" = 2 &&
	test "$(view edge history_roots)" = "$(view b history_roots)"
'

test_expect_success 'both nodes report seq 4 of 4; the backend loads both segments' '
	ingest &&
	report 2 &&
	ak_record edge &&
	ak_record b &&
	test "$(ak edge)" != "$(ak b)" &&
	latest_cmp edge &&
	latest_cmp b &&
	refresh node_ops_mv node_status_mv &&
	printf "%s\thealthy\t0\n" "$(ak b)" "$(ak edge)" | sort >"$W/status" &&
	status_cmp "$W/status" &&
	for n in edge b; do
		status_log "$n" >"$W/log-$n" &&
		grep -qx "5 head: pass, seq 4 of 4, generation 4" "$W/log-$n" || exit 1
	done
'

# No walk: each node fetches the tag and, to apply the delete at seq 5,
# its package's manifest, which bpm tree append stores in the tree's
# repository; never a sealed segment, by digest or by tag.
test_expect_success 'append 5 seals segment 2; neither node walks' '
	append 1.0.0/net-guard-1.0.0 delete &&
	walk &&
	python3 "$CHECKS" segments "$W/walk" >"$W/segments" &&
	printf "%s\t%s\t%s\n" 0 2 2 2 4 4 4 5 5 >"$W/bounds.expected" &&
	cut -f 1-3 "$W/segments" | diff -u "$W/bounds.expected" - >&2 &&
	head -n 2 "$W/segments" | diff -u "$W/segments-4" - >&2 &&
	sync_node edge step-4 >"$W/fetched-edge" &&
	sync_node b step-4 >"$W/fetched-b" &&
	cut -f 4 "$W/segments" | head -n 2 >"$W/sealed" &&
	{
		echo stable &&
		python3 "$CHECKS" artifacts "$W/walk" 5 | sed "s/^/sha256:/"
	} | sort -u >"$W/fetched.expected" &&
	{
		sort -u "$W/fetched-edge" | diff -u "$W/fetched.expected" - >&2 &&
		sort -u "$W/fetched-b" | diff -u "$W/fetched.expected" - >&2 &&
		! grep -q "segment-" "$W/requests-edge" "$W/requests-b" &&
		! grep -qFf "$W/sealed" "$W/requests-edge" "$W/requests-b" ||
		{
			sed "s/^/sealed: /" "$W/sealed" >&2
			sed "s/^/edge: /" "$W/requests-edge" >&2
			sed "s/^/b: /" "$W/requests-b" >&2
			false
		}
	} &&
	printf "xfs-fix %s\n" "$(cat "$W/payload-xfs-fix-1.1.0")" >"$W/loaded" &&
	node_check edge role=edge 5 VUA= "1 2 3 4 5" "$W/loaded" &&
	: >"$W/loaded" &&
	node_check b role=core 5 mkA= "2 5" "$W/loaded" &&
	for n in edge b; do
		test "$(view "$n" segment_base_seq)" = 4 || exit 1
	done
'

test_expect_success 'the publisher chains three segments by sealed digest and history_root' '
	cut -f 4 "$W/segments" | head -n 2 >"$W/sealed" &&
	python3 "$CHECKS" tags "$REGISTRY" "$E2E/ca.pem" "$REPOSITORY" 2 |
		diff -u "$W/sealed" - >&2 &&
	cut -f 5 "$W/segments" | tail -n 2 | diff -u "$W/sealed" - >&2 &&
	python3 "$CHECKS" operations "$W/walk" | cut -f 4 >"$W/digests" &&
	test "$(wc -l <"$W/digests")" = 5 &&
	for at in 2 4; do
		test "$(python3 "$CHECKS" roots $(head -n "$at" "$W/digests") |
			cut -d " " -f 2)" = \
			"$(awk -F "\t" -v at="$at" "\$1 == at { print \$6 }" "$W/segments")" ||
		exit 1
	done
'

test_expect_success 'each keepalive covers all five operations from base_seq 0' '
	report 4 &&
	for n in edge b; do
		test "$(view "$n" base_seq)" = 0 &&
		latest_cmp "$n" &&
		on "$n" "$RUNTIME status --keepalive" >"$W/keepalive-$n" &&
		python3 - "$W/keepalive-$n" "$W/view-$n" <<-\PY || exit 1
		import json, sys
		body, view = (json.load(open(p)) for p in sys.argv[1:3])
		for key in "base_seq", "base_root", "mask", "last_seq", "projection_root":
		    assert body[key] == view[key], (key, body[key], view[key])
		assert body["base_seq"] == 0 and body["last_seq"] == 5, body
		PY
	done
'

test_expect_success 'the backend holds one tree of three segments; both nodes healthy' '
	ingest &&
	sed "s/\t-\t/\t\t/" "$W/segments" >"$W/pubs" &&
	ch_cmp "SELECT segment_base_seq, head_seq, generation, manifest_digest,
		segment_manifest_digest, history_root
		FROM shirudo.tree_pubs FINAL WHERE tree_id = '\''$TREE_ID'\''
		ORDER BY generation" "$W/pubs" &&
	python3 "$CHECKS" operations "$W/walk" >"$W/ops" &&
	ch_cmp "SELECT seq, op, id, operation_digest FROM shirudo.tree_ops FINAL
		WHERE tree_id = '\''$TREE_ID'\'' ORDER BY seq" "$W/ops" &&
	refresh node_ops_mv history_contradictions_mv node_status_mv &&
	history_cmp edge 0 &&
	history_cmp b 0 &&
	test "$(ch "SELECT count() FROM shirudo.history_contradictions")" = 0 &&
	printf "%s\thealthy\t0\n" "$(ak b)" "$(ak edge)" | sort >"$W/status" &&
	status_cmp "$W/status" &&
	status_log edge >"$W/log-edge" &&
	status_log b >"$W/log-b" &&
	root_edge=$(view edge projection_root | cut -c 1-8) &&
	root_b=$(view b projection_root | cut -c 1-8) &&
	grep -qx "4 chain: pass, root $root_edge" "$W/log-edge" &&
	grep -qx "5 head: pass, seq 5 of 5, generation 5" "$W/log-edge" &&
	grep -qx "6 set: pass, 1 loaded" "$W/log-edge" &&
	grep -qx "4 chain: pass, root $root_b" "$W/log-b" &&
	grep -qx "5 head: pass, seq 5 of 5, generation 5" "$W/log-b" &&
	grep -qx "6 set: pass, 0 loaded" "$W/log-b"
'

test_done
