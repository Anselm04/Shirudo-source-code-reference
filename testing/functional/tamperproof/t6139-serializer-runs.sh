#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6139 -- repeated and concurrent serializer runs neither lose nor change
# records. A peek leaves the interval as it was, so two peeks report the
# same records; two drains started at once take turns at the operation
# lock, and every record ends up in exactly one of them, counted whole.
# The records are the execs of a marker program kernel-obs observes.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
UNLOAD="$FIXTURES/kernel-obs.unload.upatch"
RUNS=7
[ -s "$UNLOAD" ] || test_skip_all "missing kernel-obs unload fixture"
[ -x /usr/bin/true ] || test_skip_all "no /usr/bin/true to copy"
require_loaded kernel-obs || test_skip_all "cannot load kernel-obs"
W=$(mktemp -d)
trap '"$SHIRUDO_BIN" upatch unload "$UNLOAD" >/dev/null 2>&1 || true; rm -rf "$W"' EXIT
MARKER=$W/t6139-marker
cp /usr/bin/true "$MARKER"

# The exec count of the marker across the records of the NDJSON files.
execs() {
	python3 - "$MARKER" "$@" <<'PY'
import json, sys
marker, total = sys.argv[1], 0
for path in sys.argv[2:]:
    with open(path) as f:
        for line in f:
            doc = json.loads(line)
            if isinstance(doc, dict) and doc.get("map") == "exec":
                total += sum(int(r["exec_count"]) for r in doc["records"]
                             if r["path"] == marker)
print(total)
PY
}

# Export the exec table to the NDJSON file $1, with options to follow.
export_exec() {
	out=$1
	shift
	"$SHIRUDO_BIN" upatch map kernel-obs exec "--json=$out" "$@" \
		>/dev/null 2>"$out.err"
}

test_expect_success 'the marker runs into a drained table' '
	export_exec "$W/before.ndjson" &&
	i=0 &&
	while [ "$i" -lt "$RUNS" ]; do
		"$MARKER" || return 1
		i=$((i + 1))
	done
'

test_expect_success 'two peeks report the same records' '
	export_exec "$W/peek1.ndjson" --peek &&
	export_exec "$W/peek2.ndjson" --peek &&
	[ "$(execs "$W/peek1.ndjson")" = "$RUNS" ] &&
	[ "$(execs "$W/peek2.ndjson")" = "$RUNS" ]
'

test_expect_success 'two drains at once take each record once and whole' '
	export_exec "$W/drain1.ndjson" &
	a=$!
	export_exec "$W/drain2.ndjson" &
	b=$!
	wait "$a" && wait "$b" &&
	[ "$(execs "$W/drain1.ndjson" "$W/drain2.ndjson")" = "$RUNS" ] &&
	{ [ "$(execs "$W/drain1.ndjson")" = 0 ] ||
	  [ "$(execs "$W/drain2.ndjson")" = 0 ]; }
'

test_expect_success 'and leave none of them behind' '
	export_exec "$W/after.ndjson" --peek &&
	[ "$(execs "$W/after.ndjson")" = 0 ]
'

test_done
