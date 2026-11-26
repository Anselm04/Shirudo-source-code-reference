#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7108 -- a node walks back through the sealed segments of a tree that bpm
# tree append published with --segment-ops 2 and applies them oldest first,
# with the same tree eventlog, register events, projection root and outcomes
# as the operations taken from one publication. A node inside the current
# segment fetches only it; a walk stopped between segments or with an
# operation pending resumes with a shorter one and applies nothing twice; a
# forked base, a forked prefix, a missing sealed segment, a broken link and
# a walk past either limit are refused before anything applies; init reads
# the state and walks nothing. bpm tree show --walk, which the bundle ran on
# the operator host when it published the tree, printed every segment
# oldest first. Its own VM: the node starts without a tree.
# The bundle lowers the limits to 4 operations from a cursor past 0 and 6
# from 0.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
SOURCE="$FIXTURES/segments-oci"
TREE_DIR=/var/lib/shirudo/bpm/upatch-tree
TREE_EVENTLOG=$TREE_DIR/tree-eventlog
PENDING=$TREE_DIR/pending.json
EVENTLOG=/var/lib/shirudo/eventlog
WORK=$(mktemp -d)
SERVED="$WORK/registry"
REPO="$SERVED/shirudo/segments"
LOG="$WORK/requests.log"
SERVER_PID=
HOLDER_PID=

for fixture in "$SOURCE/port" "$SOURCE/shirudo/segments/manifests/g28" \
	"$SOURCE/shirudo/segments/manifests/fork-base" \
	"$SOURCE/shirudo/segments/manifests/fork-prefix" \
	"$SOURCE/shirudo/segments/manifests/head-gap" \
	"$SHIRUDO_TEST_KEY_FIXTURES/config-tree-segments.img" \
	"$FIXTURES/segments-show-walk.json" \
	./helper/test-oci-registry.py
do
	[ -s "$fixture" ] || test_skip_all "missing segment fixture: $fixture"
done
[ ! -e "$TREE_STATE_FILE" ] || test_skip_all "the node already follows a tree"
PORT=$(cat "$SOURCE/port")

release_tree_eventlog()
{
	[ -n "$HOLDER_PID" ] || return 0
	kill "$HOLDER_PID" 2>/dev/null || true
	wait "$HOLDER_PID" 2>/dev/null || true
	HOLDER_PID=
}

cleanup()
{
	release_tree_eventlog
	rm -f "$REPO"/manifests/*.hold
	if [ -n "$SERVER_PID" ]; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

# What the node should hold after the first $2 operations of the tree, as
# one publication of them gives it, and the digest of a manifest.
cat >"$WORK/segments.py" <<\PY
import hashlib
import json
import pathlib
import sys

DOC = "application/vnd.shirudo.upatch.tree.v1+json"
TREE = pathlib.Path("/var/lib/shirudo/bpm/upatch-tree")
repo = pathlib.Path(sys.argv[1])


def manifest(ref):
    return (repo / "manifests" / ref).read_bytes()


def digest(body):
    return "sha256:" + hashlib.sha256(body).hexdigest()


def document(ref):
    layers = json.loads(manifest(ref))["layers"]
    blob = [layer for layer in layers if layer["mediaType"] == DOC][0]
    return json.loads((repo / "blobs" / blob["digest"]).read_bytes())


def operations(n):
    ops = []
    for k in range(2, 29, 2):
        ops += document("g%d" % k)["operations"]
    assert [op["seq"] for op in ops] == list(range(1, 29)), ops
    return ops[:n]


def lines(path):
    return [json.loads(text)
            for text in path.read_text(encoding="utf-8").splitlines()]


def agree(n):
    projection, history = bytes(32), bytes(32)
    log, outcomes, measured = [], [], []
    for op in operations(n):
        raw = bytes.fromhex(op["operation_digest"][len("sha256:"):])
        history = hashlib.sha256(b"shirudo-tree-history\0" + history +
                                 raw).digest()
        matched = op["selector"]["labels"]["env"] == ["tree-test"]
        if matched:
            projection = hashlib.sha256(projection + raw).digest()
            log.append((op["seq"], op["operation_digest"], projection.hex()))
            measured.append((op["seq"], op["operation_digest"]))
        outcomes.append((op["seq"], 1 if matched else 2, projection.hex(),
                         history.hex()))
    got = [(l["seq"], l["digest"], l["projection_root"])
           for l in lines(TREE / "tree-eventlog")]
    assert got == log, ("tree-eventlog", got, log)
    got = [(l["seq"], l["outcome"], l["projection_root"], l["history_root"])
           for l in lines(TREE / "outcomes")]
    assert got == outcomes, ("outcomes", got, outcomes)
    got = [(r["tree"]["seq"], r["tree"]["operation_digest"])
           for r in lines(pathlib.Path("/var/lib/shirudo/eventlog"))
           if r.get("type") == "tree_op"]
    assert got == measured, ("tree_op records", got, measured)
    state = json.loads((TREE / "state.json").read_bytes())
    assert state["last_seq"] == n, state
    assert state["projection_root"] == projection.hex(), state
    assert state["projection_root_tpm"] == projection.hex(), state


# bpm tree show --walk of the tag at g28: every segment as plain show
# prints it, oldest first, each naming the one before.
def walked(path):
    expected = b""
    for k in range(2, 29, 2):
        raw = manifest("g%d" % k)
        layers = json.loads(raw)["layers"]
        blob = [layer for layer in layers if layer["mediaType"] == DOC][0]
        expected += (b'{"manifest_digest":"' + digest(raw).encode() +
                     b'","document":' +
                     (repo / "blobs" / blob["digest"]).read_bytes() + b"}\n")
    shown = path.read_bytes()
    assert shown == expected, ("bpm tree show --walk", shown)
    decoder, text, before = json.JSONDecoder(), shown.decode(), None
    for k in range(0, 28, 2):
        segment, end = decoder.raw_decode(text)
        text = text[end + 1:]
        base = segment["document"]["base"]
        assert base["seq"] == k, segment
        assert base.get("segment_manifest_digest") == before, segment
        before = segment["manifest_digest"]
    assert text == "", text


if sys.argv[2] == "digest":
    print(digest(manifest(sys.argv[3])))
elif sys.argv[2] == "walked":
    walked(pathlib.Path(sys.argv[3]))
elif sys.argv[2] == "agree":
    agree(int(sys.argv[3]))
else:
    sys.exit("unknown command " + sys.argv[2])
PY

segments()
{
	python3 "$WORK/segments.py" "$REPO" "$@"
}

# The digest of the manifest the reference $1 names.
digest_of()
{
	segments digest "$1"
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

# The requests the registry logged since it had $1 lines.
requests_since()
{
	sed -n "$(($1 + 1)),\$p" "$LOG"
}

# How many GETs of the manifest $2 the requests since line $1 hold.
manifest_gets()
{
	requests_since "$1" | grep -c "^GET	/v2/shirudo/segments/manifests/$2	" || :
}

state_is()
{
	[ "$(tree_state_field last_seq)" = "$1" ] &&
	[ "$(tree_state_field generation)" = "$2" ] &&
	[ "$(tree_state_field segment_base_seq)" = "$3" ] &&
	[ "$(tree_state_field head_seq)" = "$4" ]
}

hold_tree_eventlog()
{
	python3 -c '
import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_RDONLY)
fcntl.flock(fd, fcntl.LOCK_EX)
open(sys.argv[2], "w").close()
time.sleep(600)
' "$TREE_EVENTLOG" "$WORK/held" &
	HOLDER_PID=$!
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		[ -e "$WORK/held" ] && return 0
		sleep 1
	done
	return 1
}

tree_op_measured()
{
	python3 - "$EVENTLOG" "$1" <<'PY'
import json
import sys
import time

seq = int(sys.argv[2])
for _ in range(600):
    with open(sys.argv[1], encoding="utf-8") as stream:
        for text in stream:
            try:
                record = json.loads(text)
            except ValueError:
                continue
            if record.get("type") == "tree_op" and \
               record.get("tree", {}).get("seq") == seq:
                sys.exit(0)
    time.sleep(0.1)
sys.exit(1)
PY
}

# Wait until the registry holds the request the file $1 marks.
request_held()
{
	for _ in $(seq 100); do
		[ -e "$1" ] && return 0
		sleep 0.1
	done
	return 1
}

cp -R "$SOURCE" "$SERVED"
python3 ./helper/test-oci-registry.py --root "$SERVED" --port "$PORT" \
	--log "$LOG" --ready-file "$WORK/ready" &
SERVER_PID=$!
for _ in 1 2 3 4 5; do
	[ -e "$WORK/ready" ] && break
	sleep 1
done
[ -e "$WORK/ready" ] || test_skip_all "the segment registry did not start"
"$SHIRUDO_BIN" image update "$SHIRUDO_TEST_KEY_FIXTURES/config-tree-segments" \
	>/dev/null || test_skip_all "cannot activate config-tree-segments"
G2=$(digest_of g2) && G4=$(digest_of g4) && G6=$(digest_of g6) &&
G12=$(digest_of g12) && G14=$(digest_of g14) && G18=$(digest_of g18) &&
G22=$(digest_of g22) || test_skip_all "cannot read the segment fixtures"

test_expect_success 'a joining node refuses a walk past its limit before it fetches a sealed segment' '
	serve g9 &&
	n=$(wc -l <"$LOG") &&
	! sync_tree join-limit &&
	grep -q "phase=segment_walk rc=-7 " "$WORK/join-limit.err" &&
	! requests_since "$n" | grep -q "/manifests/sha256:" &&
	[ ! -e "$TREE_STATE_FILE" ] &&
	[ ! -e "$TREE_EVENTLOG" ]
'

test_expect_success 'a new node walks back past the running limit through four segments and applies them in order' '
	serve g8 &&
	n=$(wc -l <"$LOG") &&
	sync_tree join &&
	[ "$(report_field selected <"$WORK/join.json")" = 5 ] &&
	[ "$(report_field skipped <"$WORK/join.json")" = 3 ] &&
	[ "$(report_field applied <"$WORK/join.json")" = 5 ] &&
	[ "$(report_field last_seq <"$WORK/join.json")" = 8 ] &&
	[ "$(manifest_gets "$n" "$G2")" = 2 ] &&
	[ "$(manifest_gets "$n" "$G4")" = 2 ] &&
	[ "$(manifest_gets "$n" "$G6")" = 2 ] &&
	state_is 8 8 6 8 &&
	segments agree 8 &&
	"$SHIRUDO_BIN" status --json | python3 -c "
import json, sys
assert json.load(sys.stdin)[\"tpm\"][\"chain_matches_eventlog\"] is True
"
'

test_expect_success 'a node inside the current segment fetches only it' '
	serve g9 &&
	sync_tree current-start &&
	state_is 9 9 8 9 &&
	serve g10 &&
	n=$(wc -l <"$LOG") &&
	sync_tree current &&
	[ "$(report_field applied <"$WORK/current.json")" = 1 ] &&
	[ "$(manifest_gets "$n" segments)" = 1 ] &&
	! requests_since "$n" | grep -q "/manifests/sha256:" &&
	state_is 10 10 8 10 &&
	segments agree 10
'

# A test body runs in a subshell, which could not hand a holder process to
# the cleanup: stop each sync here and let the bodies look at what is left.
serve g16
printf '2\n' >"$REPO/manifests/$G14.hold"
BETWEEN=no
BPM_OCI_SCHEME=http "$SHIRUDO_BIN" bpm tree sync \
	--report "$WORK/between.json" >/dev/null 2>&1 &
SYNC_PID=$!
request_held "$REPO/manifests/$G14.held" && BETWEEN=yes
kill -9 "$SYNC_PID" 2>/dev/null || true
wait "$SYNC_PID" 2>/dev/null || true
rm -f "$REPO/manifests/$G14.hold"

test_expect_success 'a walk stopped between two segments leaves the first applied and recorded' '
	[ "$BETWEEN" = yes ] &&
	[ ! -e "$WORK/between.json" ] &&
	[ ! -e "$PENDING" ] &&
	state_is 12 12 10 12 &&
	segments agree 12
'

test_expect_success 'the next sync walks back only to the segment not applied' '
	n=$(wc -l <"$LOG") &&
	sync_tree resumed &&
	[ "$(manifest_gets "$n" "$G12")" = 0 ] &&
	[ "$(manifest_gets "$n" "$G14")" = 2 ] &&
	[ "$(report_field applied <"$WORK/resumed.json")" = 3 ] &&
	state_is 16 16 14 16 &&
	segments agree 16
'

serve g20
PENDED=no
if hold_tree_eventlog; then
	BPM_OCI_SCHEME=http "$SHIRUDO_BIN" bpm tree sync \
		--report "$WORK/pended.json" >/dev/null 2>&1 &
	SYNC_PID=$!
	tree_op_measured 18 && PENDED=yes
	kill -9 "$SYNC_PID" 2>/dev/null || true
	wait "$SYNC_PID" 2>/dev/null || true
fi
release_tree_eventlog

test_expect_success 'a walk stopped with an operation pending leaves its segment recorded' '
	[ "$PENDED" = yes ] &&
	[ ! -e "$WORK/pended.json" ] &&
	[ -e "$PENDING" ] &&
	state_is 16 18 16 18
'

test_expect_success 'the next sync completes it from the oldest segment of its walk, once' '
	n=$(wc -l <"$LOG") &&
	sync_tree completed &&
	[ "$(manifest_gets "$n" "$G18")" = 2 ] &&
	[ ! -e "$PENDING" ] &&
	[ "$(report_field last_seq <"$WORK/completed.json")" = 20 ] &&
	state_is 20 20 18 20 &&
	segments agree 20
'

test_expect_success 'a predecessor that does not start from the node history is refused on the base check' '
	serve fork-base &&
	! sync_tree fork-base &&
	grep -q "phase=history_base rc=-129 " "$WORK/fork-base.err" &&
	state_is 20 20 18 20 &&
	segments agree 20
'

test_expect_success 'a segment whose operations before the cursor differ is refused on the prefix check' '
	serve fork-prefix &&
	! sync_tree fork-prefix &&
	grep -q "phase=history_prefix rc=-129 " "$WORK/fork-prefix.err" &&
	state_is 20 20 18 20 &&
	segments agree 20
'

test_expect_success 'a sealed segment the registry lost refuses the sync with nothing applied' '
	serve g24 &&
	mv "$REPO/manifests/$G22" "$WORK/sealed" &&
	n=$(wc -l <"$LOG") &&
	! sync_tree lost &&
	mv "$WORK/sealed" "$REPO/manifests/$G22" &&
	grep -q "phase=segment_fetch rc=-2 " "$WORK/lost.err" &&
	requests_since "$n" |
		grep -q "^GET	/v2/shirudo/segments/manifests/$G22	404$" &&
	state_is 20 20 18 20 &&
	segments agree 20
'

test_expect_success 'a predecessor that ends before the base of its successor is refused' '
	serve head-gap &&
	! sync_tree head-gap &&
	grep -q "phase=segment_chain rc=-34 " "$WORK/head-gap.err" &&
	state_is 20 20 18 20
'

test_expect_success 'a running node refuses a walk past its limit before anything applies' '
	serve g28 &&
	n=$(wc -l <"$LOG") &&
	! sync_tree walk-limit &&
	grep -q "phase=segment_walk rc=-7 " "$WORK/walk-limit.err" &&
	! requests_since "$n" | grep -q "/manifests/sha256:" &&
	state_is 20 20 18 20 &&
	segments agree 20
'

test_expect_success 'a dry run walks and checks every segment and records nothing' '
	serve g24 &&
	BPM_OCI_SCHEME=http "$SHIRUDO_BIN" bpm tree sync --dry-run \
		--report "$WORK/dry.json" >/dev/null &&
	[ "$(report_field selected <"$WORK/dry.json")" = 3 ] &&
	[ "$(report_field skipped <"$WORK/dry.json")" = 1 ] &&
	[ "$(report_field applied <"$WORK/dry.json")" = 0 ] &&
	[ "$(report_field last_seq <"$WORK/dry.json")" = 20 ] &&
	state_is 20 20 18 20 &&
	segments agree 20
'

test_expect_success 'the node catches up with the segments the registry serves again' '
	sync_tree caught-up &&
	[ "$(report_field applied <"$WORK/caught-up.json")" = 3 ] &&
	state_is 24 24 22 24 &&
	segments agree 24
'

test_expect_success 'init mid-tree walks nothing and takes the projection root one publication gives' '
	n=$(wc -l <"$LOG") &&
	lines=$(wc -l <"$EVENTLOG") &&
	"$SHIRUDO_BIN" init >/dev/null &&
	[ "$(wc -l <"$LOG")" = "$n" ] &&
	[ "$(wc -l <"$EVENTLOG")" = "$lines" ] &&
	segments agree 24
'

test_expect_success 'bpm tree show --walk printed every segment, oldest first' '
	segments walked "$FIXTURES/segments-show-walk.json"
'

test_done
