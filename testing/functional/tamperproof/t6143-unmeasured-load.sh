#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6143 -- a load stopped between its pins and its extend cannot keep a
# upatch running unmeasured: the signal that stopped it is counted,
# status reports the pins the register does not cover as tampered, and
# the next upatch command, a load or an unload of another upatch, undoes
# them before it acts.

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
ARCHIVE="/var/lib/shirudo/upatches/$NAME.upatch"
EVENTLOG=/var/lib/shirudo/eventlog
W=$(mktemp -d)
cleanup() {
	[ ! -e "$OTHERDIR" ] ||
		"$SHIRUDO_BIN" upatch unload "$FIXTURES/$OTHER.unload.upatch" \
			>/dev/null 2>&1 || :
	[ ! -e "$PINDIR" ] ||
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" >/dev/null 2>&1 || :
	rm -rf "$W"
}
trap cleanup EXIT
for f in "$LOAD" "$UNLOAD" "$FIXTURES/$OTHER.upatch" \
	 "$FIXTURES/$OTHER.unload.upatch"; do
	[ -s "$f" ] || test_skip_all "missing fixture $f"
done
[ -s "$EVENTLOG" ] || test_skip_all "no eventlog"
counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
print(json.load(sys.stdin)["tamper_attempts"]["counters"][sys.argv[1]])
' "$1"
}
before=$(counter SealSignal) || test_skip_all "no tamper counters"
# An earlier test of the family may have left either loaded.
[ ! -e "$PINDIR" ] || "$SHIRUDO_BIN" upatch unload "$UNLOAD" >/dev/null 2>&1
[ ! -e "$OTHERDIR" ] ||
	"$SHIRUDO_BIN" upatch unload "$FIXTURES/$OTHER.unload.upatch" \
		>/dev/null 2>&1
for d in "$PINDIR" "$OTHERDIR"; do
	[ ! -e "$d" ] || test_skip_all "$(basename "$d") cannot be unloaded"
done

# Start a load and stop it once its link pin appears, before the
# register moves. A load that got as far as its record, which the
# eventlog shows as one more line, is unloaded and tried again. The
# poll is builtins only, so that it runs faster than the extend, and
# bounded, as a load that fails stays a zombie until it is waited for.
stopped_load() {
	for try in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
		lines=$(wc -l <"$EVENTLOG")
		"$SHIRUDO_BIN" upatch load "$LOAD" >/dev/null 2>&1 &
		pid=$!
		i=0
		while kill -0 "$pid" 2>/dev/null && [ ! -e "$PINDIR/link" ] &&
		      [ "$i" -lt 2000000 ]; do
			i=$((i + 1))
		done
		kill -9 "$pid" 2>/dev/null || :
		wait "$pid" 2>/dev/null || :
		if [ -e "$PINDIR/link" ] &&
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

test_expect_success 'a load stopped before its extend leaves pins without a record' '
	stopped_load &&
	[ -e "$PINDIR/link" ] &&
	[ ! -e "$ARCHIVE" ]
'
test_expect_success 'the signal that stopped the load is counted as SealSignal' '
	[ "$(counter SealSignal)" -ge $((before + 1)) ]
'
test_expect_success 'status reports the unmeasured pins as tampered' '
	"$SHIRUDO_BIN" status --json >"$W/status.json" 2>/dev/null &&
	measured_condition "$W/status.json" >"$W/cond" &&
	read -r verdict cond detail <"$W/cond" &&
	[ "$verdict" = tampered ] &&
	[ "$cond" = ALERT ] &&
	case "$detail" in *"$NAME"*) true ;; *) false ;; esac &&
	"$SHIRUDO_BIN" status 2>/dev/null | grep -q "^Status: *tampered" &&
	"$SHIRUDO_BIN" status 2>/dev/null | grep -q "UpatchesMeasured *ALERT"
'
test_expect_success 'the next load undoes the unmeasured pins before it acts' '
	"$SHIRUDO_BIN" upatch load "$FIXTURES/$OTHER.upatch" >/dev/null 2>&1 &&
	[ ! -e "$PINDIR" ] &&
	[ -e "$OTHERDIR/link" ] &&
	"$SHIRUDO_BIN" status --json >"$W/status.json" 2>/dev/null &&
	measured_condition "$W/status.json" >"$W/cond" &&
	read -r verdict cond detail <"$W/cond" &&
	[ "$verdict" != tampered ] &&
	[ "$cond" = OK ]
'
test_expect_success 'the next unload undoes the unmeasured pins before it acts' '
	stopped_load &&
	"$SHIRUDO_BIN" upatch unload "$FIXTURES/$OTHER.unload.upatch" \
		>/dev/null 2>&1 &&
	[ ! -e "$PINDIR" ] &&
	[ ! -e "$OTHERDIR" ] &&
	"$SHIRUDO_BIN" status --json >"$W/status.json" 2>/dev/null &&
	measured_condition "$W/status.json" >"$W/cond" &&
	read -r verdict cond detail <"$W/cond" &&
	[ "$verdict" != tampered ] &&
	[ "$cond" = OK ]
'
test_expect_success 'a load after the undo is measured again' '
	"$SHIRUDO_BIN" upatch load "$LOAD" >/dev/null 2>&1 &&
	[ -e "$PINDIR/link" ] &&
	[ -s "$ARCHIVE" ] &&
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" >/dev/null 2>&1 &&
	[ ! -e "$PINDIR" ]
'
test_done
