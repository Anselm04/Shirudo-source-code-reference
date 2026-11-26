#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7113 -- a pending operation the node stopped matching and passed does not
# stop the node: a sync stopped after writing pending.json for an operation
# and before measuring it, then a sync under labels no operation selects,
# which passes the operation and leaves its record behind the cursor, and
# then a sync of the next segment, which no longer holds the operation,
# removes the record and goes on. On the tree t7108 walks, in a VM of its
# own, as the node starts without a tree.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
SOURCE="$FIXTURES/segments-oci"
PENDING=/var/lib/shirudo/bpm/upatch-tree/pending.json
WORK=$(mktemp -d)
SERVED="$WORK/registry"
REPO="$SERVED/shirudo/segments"
SERVER_PID=

for fixture in "$SOURCE/port" "$SOURCE/shirudo/segments/manifests/g4" \
	"$SHIRUDO_TEST_KEY_FIXTURES/config-tree-segments-other.img" \
	"$SHIRUDO_TEST_KEY_FIXTURES/config-tree-segments-none.img" \
	./helper/test-oci-registry.py
do
	[ -s "$fixture" ] || test_skip_all "missing segment fixture: $fixture"
done
[ ! -e "$TREE_STATE_FILE" ] || test_skip_all "the node already follows a tree"
PORT=$(cat "$SOURCE/port")

cleanup()
{
	if [ -n "$SERVER_PID" ]; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

# The manifest digest of the artifact of operation $2 of the publication
# the reference $1 names.
artifact_of()
{
	python3 - "$REPO" "$1" "$2" <<'PY'
import json
import pathlib
import sys

DOC = "application/vnd.shirudo.upatch.tree.v1+json"
repo, ref, seq = pathlib.Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
layers = json.loads((repo / "manifests" / ref).read_bytes())["layers"]
blob = [layer for layer in layers if layer["mediaType"] == DOC][0]
document = json.loads((repo / "blobs" / blob["digest"]).read_bytes())
print([op for op in document["operations"]
       if op["seq"] == seq][0]["artifact"]["manifest_digest"])
PY
}

# The target follows the reference segments, which names generation $1.
serve()
{
	cp "$REPO/manifests/$1" "$REPO/manifests/segments"
}

sync_tree()
{
	BPM_OCI_SCHEME=http "$SHIRUDO_BIN" bpm tree sync \
		--report "$WORK/$1.json" >/dev/null 2>"$WORK/$1.err"
}

state_is()
{
	[ "$(tree_state_field last_seq)" = "$1" ] &&
	[ "$(tree_state_field generation)" = "$2" ] &&
	[ "$(tree_state_field segment_base_seq)" = "$3" ] &&
	[ "$(tree_state_field head_seq)" = "$4" ]
}

cp -R "$SOURCE" "$SERVED"
python3 ./helper/test-oci-registry.py --root "$SERVED" --port "$PORT" \
	--ready-file "$WORK/ready" &
SERVER_PID=$!
for _ in 1 2 3 4 5; do
	[ -e "$WORK/ready" ] && break
	sleep 1
done
[ -e "$WORK/ready" ] || test_skip_all "the segment registry did not start"
# Operation 2 adds the upatch the labels env=not-this-node select, which no
# sync fetched before: with its manifest gone the sync stops after writing
# pending.json and before measuring the operation.
OTHER=$(artifact_of g2 2) || test_skip_all "cannot read the segment fixtures"

test_expect_success 'a sync stopped before measuring an operation leaves it pending' '
	"$SHIRUDO_BIN" image update \
		"$SHIRUDO_TEST_KEY_FIXTURES/config-tree-segments-other" >/dev/null &&
	serve g2 &&
	mv "$REPO/manifests/$OTHER" "$WORK/other-manifest" &&
	! sync_tree stopped &&
	mv "$WORK/other-manifest" "$REPO/manifests/$OTHER" &&
	grep -q "phase=artifact_fetch_or_verify " "$WORK/stopped.err" &&
	[ -e "$PENDING" ] &&
	state_is 0 2 0 2
'

test_expect_success 'a sync under labels no operation selects passes it and leaves its record' '
	"$SHIRUDO_BIN" image update \
		"$SHIRUDO_TEST_KEY_FIXTURES/config-tree-segments-none" >/dev/null &&
	sync_tree passed &&
	[ "$(report_field applied <"$WORK/passed.json")" = 0 ] &&
	[ -e "$PENDING" ] &&
	state_is 2 2 0 2
'

test_expect_success 'the next segment, which no longer holds the operation, syncs and removes its record' '
	serve g4 &&
	sync_tree next &&
	[ ! -e "$PENDING" ] &&
	[ "$(report_field last_seq <"$WORK/next.json")" = 4 ] &&
	state_is 4 4 2 4
'

test_expect_success 'a sync after it goes on from there' '
	serve g6 &&
	sync_tree after &&
	state_is 6 6 4 6
'

test_done
