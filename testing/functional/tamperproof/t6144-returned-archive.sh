#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6144 -- the archive directory after its mark is evicted, and an
# archive the eventlog does not cover. The seal reads the directory's
# label in the entry hooks, so evicting the cache opens nothing: a hard
# link of a labeled archive out of the directory, and a file, a link or
# a rename into it, are refused with the mark gone, while shirudo's own
# load still labels what it archives. An archive without a record of
# its load, which a load stopped between its archive copy and its
# extend leaves, is reported by status, ignored by init and removed by
# the next upatch command.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
FIXTURES=$SHIRUDO_TEST_FIXTURES_DIR
NAME=shirudo-test-basic
OTHER=shirudo-test-marker
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PINDIR="/run/shirudo/bpffs/upatches/$NAME"
OTHERDIR="/run/shirudo/bpffs/upatches/$OTHER"
UPDIR=/var/lib/shirudo/upatches
ARCHIVE="$UPDIR/$NAME.upatch"
EVENTLOG=/var/lib/shirudo/eventlog
KEEPDIR=/var/lib/t6144
W=$(mktemp -d)
cleanup() {
	[ ! -e "$OTHERDIR" ] ||
		"$SHIRUDO_BIN" upatch unload "$FIXTURES/$OTHER.unload.upatch" \
			>/dev/null 2>&1 || :
	[ ! -e "$PINDIR" ] ||
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" >/dev/null 2>&1 || :
	rm -rf "$KEEPDIR" "$W" 2>/dev/null || :
}
trap cleanup EXIT
for f in "$LOAD" "$UNLOAD" "$FIXTURES/$OTHER.upatch" \
	 "$FIXTURES/$OTHER.unload.upatch"; do
	[ -s "$f" ] || test_skip_all "missing fixture $f"
done
[ ! -e "$PINDIR" ] || "$SHIRUDO_BIN" upatch unload "$UNLOAD" >/dev/null 2>&1
[ ! -e "$OTHERDIR" ] ||
	"$SHIRUDO_BIN" upatch unload "$FIXTURES/$OTHER.unload.upatch" \
		>/dev/null 2>&1
for d in "$PINDIR" "$OTHERDIR"; do
	[ ! -e "$d" ] || test_skip_all "$(basename "$d") cannot be unloaded"
done
[ ! -e "$ARCHIVE" ] || test_skip_all "$NAME is archived already"
mkdir -p "$KEEPDIR"

counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
print(json.load(sys.stdin)["tamper_attempts"]["counters"][sys.argv[1]])
' "$1"
}
label_len() {
	python3 -c 'import os, sys
print(len(os.getxattr(sys.argv[1], "security.bpf.shirudo")))' "$1"
}
evict() {
	sync && echo 2 >/proc/sys/vm/drop_caches
}

# Start a load and stop it once its archive copy appears, before the
# register moves. A load that got as far as its record, which the
# eventlog shows as one more line, is unloaded and tried again. The
# poll is builtins only and bounded, as a load that fails stays a
# zombie until it is waited for.
stopped_load() {
	for try in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
		lines=$(wc -l <"$EVENTLOG")
		"$SHIRUDO_BIN" upatch load "$LOAD" >/dev/null 2>&1 &
		pid=$!
		i=0
		while kill -0 "$pid" 2>/dev/null && [ ! -e "$ARCHIVE" ] &&
		      [ "$i" -lt 2000000 ]; do
			i=$((i + 1))
		done
		kill -9 "$pid" 2>/dev/null || :
		wait "$pid" 2>/dev/null || :
		if [ -e "$ARCHIVE" ] &&
		   [ "$(wc -l <"$EVENTLOG")" = "$lines" ]; then
			return 0
		fi
		[ ! -e "$PINDIR" ] ||
			"$SHIRUDO_BIN" upatch unload "$UNLOAD" >/dev/null 2>&1 || :
	done
	return 1
}

# The verdict and the UpatchesMeasured condition of a status document.
measured_condition() {
	python3 - "$1" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
c = [c for c in d["conditions"] if c["type"] == "UpatchesMeasured"]
print(d["status"], c[0]["status"] if c else "-", c[0]["detail"] if c else "-")
PY
}

test_expect_success 'a labeled archive cannot be hard-linked out of the archive directory' '
	before=$(counter SealEntry) &&
	"$SHIRUDO_BIN" upatch load "$LOAD" >/dev/null 2>&1 &&
	[ "$(label_len "$ARCHIVE")" = 64 ] &&
	! ln "$ARCHIVE" "$KEEPDIR/keep.upatch" 2>/dev/null &&
	[ ! -e "$KEEPDIR/keep.upatch" ] &&
	[ "$(counter SealEntry)" -ge $((before + 1)) ]
'
test_expect_success 'nothing enters the archive directory while its mark is evicted' '
	before=$(counter SealEntry) &&
	cp "$LOAD" "$KEEPDIR/plain.upatch" &&
	evict && ! touch "$UPDIR/t6144.upatch" 2>/dev/null &&
	evict && ! ln "$KEEPDIR/plain.upatch" "$UPDIR/t6144-link.upatch" 2>/dev/null &&
	evict && ! mv "$KEEPDIR/plain.upatch" "$UPDIR/t6144-moved.upatch" 2>/dev/null &&
	[ ! -e "$UPDIR/t6144.upatch" ] && [ ! -e "$UPDIR/t6144-link.upatch" ] &&
	[ ! -e "$UPDIR/t6144-moved.upatch" ] && [ -s "$KEEPDIR/plain.upatch" ] &&
	[ "$(counter SealEntry)" -ge $((before + 3)) ]
'
test_expect_success 'shirudo still labels what it archives after the eviction' '
	evict &&
	"$SHIRUDO_BIN" upatch load "$FIXTURES/$OTHER.upatch" >/dev/null 2>&1 &&
	[ "$(label_len "$UPDIR/$OTHER.upatch")" = 64 ] &&
	"$SHIRUDO_BIN" upatch unload "$FIXTURES/$OTHER.unload.upatch" \
		>/dev/null 2>&1 &&
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" >/dev/null 2>&1 &&
	[ ! -e "$ARCHIVE" ]
'
test_expect_success 'a load stopped after its archive copy leaves an archive without a record' '
	stopped_load &&
	[ -e "$ARCHIVE" ] &&
	[ -e "$PINDIR/link" ]
'
test_expect_success 'status reports the archive without a record as tampered' '
	"$SHIRUDO_BIN" status --json >"$W/status.json" 2>/dev/null &&
	measured_condition "$W/status.json" >"$W/cond" &&
	read -r verdict cond detail <"$W/cond" &&
	[ "$verdict" = tampered ] &&
	[ "$cond" = ALERT ] &&
	case "$detail" in *"$NAME"*) true ;; *) false ;; esac
'
test_expect_success 'init does not restore an archive without a record' '
	"$SHIRUDO_BIN" init >/dev/null 2>"$W/init.err" &&
	grep -q "$NAME.upatch is archived without a record of its load" \
		"$W/init.err" &&
	[ -e "$ARCHIVE" ]
'
test_expect_success 'the next upatch command removes the archive and the pins' '
	"$SHIRUDO_BIN" upatch load "$FIXTURES/$OTHER.upatch" >/dev/null 2>&1 &&
	[ ! -e "$ARCHIVE" ] &&
	[ ! -e "$PINDIR" ] &&
	[ -e "$OTHERDIR/link" ] &&
	"$SHIRUDO_BIN" status --json >"$W/status.json" 2>/dev/null &&
	measured_condition "$W/status.json" >"$W/cond" &&
	read -r verdict cond detail <"$W/cond" &&
	[ "$verdict" != tampered ] &&
	[ "$cond" = OK ] &&
	"$SHIRUDO_BIN" upatch unload "$FIXTURES/$OTHER.unload.upatch" \
		>/dev/null 2>&1 &&
	[ ! -e "$OTHERDIR" ]
'
test_done
