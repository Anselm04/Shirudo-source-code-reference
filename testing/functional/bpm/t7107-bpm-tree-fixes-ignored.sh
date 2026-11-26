#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7107 -- a node reads past the fixes of a tree operation: a publication
# whose operations carry fixes as a publisher writes it, and in forms no
# publisher writes, on a delete and on an operation without a match,
# syncs with the outcomes, state, tree eventlog and upatches the same
# operations give without the key.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
REGISTRY="$FIXTURES/tree-oci"
TREE_REPO="$REGISTRY/shirudo/upatch-tree"
TREE_DIR=/var/lib/shirudo/bpm/upatch-tree
OUTCOMES=$TREE_DIR/outcomes
TREE_EVENTLOG=$TREE_DIR/tree-eventlog
MATCH_PIN=/run/shirudo/bpffs/upatches/shirudo-test-tree-match/link
SKIP_PIN=/run/shirudo/bpffs/upatches/shirudo-test-tree-skip/link
WORK=$(mktemp -d)

for fixture in \
	"$TREE_REPO/manifests/fixes" \
	"$FIXTURES/shirudo-test-tree-skip.unload.upatch" \
	"./helper/test-oci-registry.py"
do
	[ -s "$fixture" ] || test_skip_all "missing tree fixture: $fixture"
done

[ "$(tree_state_field tree_id)" = shirudo-test-tree ] &&
	[ "$(tree_state_field last_seq)" = 13 ] &&
	[ ! -e "$MATCH_PIN" ] && [ ! -e "$SKIP_PIN" ] ||
	test_skip_all "tree state is not where t7106 leaves it"

cleanup()
{
	tree_registry_stop
	if [ -e "$SKIP_PIN" ]; then
		"$SHIRUDO_BIN" upatch unload \
			"$FIXTURES/shirudo-test-tree-skip.unload.upatch" \
			--no-precheck >/dev/null 2>&1 || true
	fi
	tree_cleanup_config
	rm -rf "$WORK"
}
trap cleanup EXIT

# The publication at the reference fixes, as the registry serves it.
DOCUMENT="$WORK/fixes.json"
python3 - "$TREE_REPO" "$DOCUMENT" <<'PY'
import json
import pathlib
import sys

repo, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
manifest = json.loads((repo / "manifests" / "fixes").read_bytes())
out.write_bytes((repo / "blobs" / manifest["layers"][0]["digest"])
                .read_bytes())
PY

tree_configure fixes
tree_registry_start "$REGISTRY" "$WORK"

test_expect_success 'the publication carries fixes outside every operation digest' '
	python3 - "$DOCUMENT" <<'"'"'PY'"'"'
import hashlib, json, sys
pub = json.load(open(sys.argv[1]))
ops = {op["seq"]: op for op in pub["operations"]}
assert ops[14]["fixes"] == ["EXAMPLE-0101"], ops[14]
assert ops[15]["op"] == "delete" and isinstance(ops[15]["fixes"], dict), ops[15]
assert len(ops[16]["fixes"]) > 16 and "" in ops[16]["fixes"], ops[16]
for op in pub["operations"]:
    canonical = {k: op[k] for k in ("seq", "op", "id", "selector", "artifact")}
    text = json.dumps(canonical, separators=(",", ":")).encode()
    assert op["operation_digest"] == "sha256:" + hashlib.sha256(text).hexdigest(), op
PY
'

test_expect_success 'the node syncs the operations as it would without fixes' '
	tree_sync "$WORK/fixes-report.json" &&
	[ "$(report_field selected <"$WORK/fixes-report.json")" = 2 ] &&
	[ "$(report_field skipped <"$WORK/fixes-report.json")" = 1 ] &&
	[ "$(report_field applied <"$WORK/fixes-report.json")" = 2 ] &&
	[ "$(report_field last_seq <"$WORK/fixes-report.json")" = 16 ] &&
	[ "$(tree_state_field generation)" = 10 ] &&
	[ "$(tree_state_field head_seq)" = 16 ] &&
	[ "$(tree_state_field last_seq)" = 16 ] &&
	[ ! -e "$MATCH_PIN" ] && [ ! -e "$SKIP_PIN" ]
'

# Lines 14 to 16 of the outcomes record are those of the operations
# without fixes: 1 for the add and the delete, 2 for the operation
# without a match, each with the history root its digest folds to and the
# projection root the tree eventlog has.
test_expect_success 'the outcomes and the tree eventlog are those of the same tree without fixes' '
	python3 - "$OUTCOMES" "$TREE_EVENTLOG" "$DOCUMENT" <<'"'"'PY'"'"'
import hashlib, json, sys
outcomes, eventlog, document = sys.argv[1:4]
pub = json.load(open(document))
digests = {op["seq"]: bytes.fromhex(op["operation_digest"][len("sha256:"):])
           for op in pub["operations"]}
applied = {}
for text in open(eventlog, encoding="utf-8").read().splitlines():
    event = json.loads(text)
    applied[event["seq"]] = event["projection_root"]
lines = [json.loads(text)
         for text in open(outcomes, encoding="utf-8").read().splitlines()]
assert [line["seq"] for line in lines] == list(range(1, 17)), lines
assert sorted(s for s in applied if s > 13) == [14, 15], applied
history = bytes(32)
projection = "00" * 32
for line in lines:
    seq = line["seq"]
    history = hashlib.sha256(b"shirudo-tree-history\0" + history +
                             digests[seq]).digest()
    projection = applied.get(seq, projection)
    assert line["history_root"] == history.hex(), line
    assert line["projection_root"] == projection, line
assert [line["outcome"] for line in lines[13:]] == [1, 1, 2], lines[13:]
PY
'

test_done
