#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3101 -- target-side integration coverage using artifacts built and signed
# by the operator-side test-vm bundle builder. This test deliberately has no
# compiler or shirudo-build dependency.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
BASIC="$FIXTURES/shirudo-test-basic.upatch"
BASIC_MISMATCH="$FIXTURES/shirudo-test-basic-mismatch.unload.upatch"
LIFECYCLE="$FIXTURES/shirudo-test-lifecycle.upatch"
LIFECYCLE_UNLOAD="$FIXTURES/shirudo-test-lifecycle.unload.upatch"
MARKER="$FIXTURES/shirudo-test-marker.upatch"
MARKER_UNLOAD="$FIXTURES/shirudo-test-marker.unload.upatch"
FOREIGN="$FIXTURES/shirudo-test-foreign.upatch"
OWN="$FIXTURES/shirudo-test-own-keyring.upatch"
OWN_CERT="$FIXTURES/own.der"
MAP_EXPORT="$FIXTURES/shirudo-test-map-export.upatch"
WORK=$(mktemp -d)
BASIC_PIN=/run/shirudo/bpffs/upatches/shirudo-test-basic/link
LIFECYCLE_PIN=/run/shirudo/bpffs/upatches/shirudo-test-lifecycle/link
MARKER_PIN=/run/shirudo/bpffs/upatches/shirudo-test-marker/link
MAP_EXPORT_PIN=/run/shirudo/bpffs/upatches/shirudo-test-map-export/link

for fixture in "$BASIC" "$BASIC_MISMATCH" \
	"$LIFECYCLE" "$LIFECYCLE_UNLOAD" "$MARKER" "$MARKER_UNLOAD" \
	"$FOREIGN" "$OWN" "$OWN_CERT" "$MAP_EXPORT" \
	"$FIXTURES/cert.der"
do
	[ -s "$fixture" ] || test_skip_all "missing target fixture: $fixture"
done

cleanup()
{
	if [ -e "$MAP_EXPORT_PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$FIXTURES/shirudo-test-map-export.unload.upatch" \
			--no-precheck >/dev/null 2>&1 || true
	fi
	if [ -e "$MARKER_PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$MARKER_UNLOAD" \
			--no-precheck >/dev/null 2>&1 || true
	fi
	if [ -e "$LIFECYCLE_PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$LIFECYCLE_UNLOAD" \
			--no-precheck >/dev/null 2>&1 || true
	fi
	# Keep the basic fixture loaded for the following remote/keyring tests.
	rm -rf "$WORK"
}
trap cleanup EXIT

test_expect_success 'prebuilt trusted fixture loads and remains archived' '
	"$SHIRUDO_BIN" upatch load "$BASIC" --no-precheck >/dev/null 2>&1 &&
	test -e "$BASIC_PIN" &&
	test -s /var/lib/shirudo/upatches/shirudo-test-basic.upatch
'

test_expect_success 'prebuilt unload binding rejects a wrong payload hash' '
	cat=$($SHIRUDO_BIN upatch unload "$BASIC_MISMATCH" --no-precheck \
		--report=- 2>/dev/null | report_field category) &&
	[ "$cat" = payload_mismatch ] &&
	test -e "$BASIC_PIN"
'

test_expect_success 'prebuilt lifecycle fixture loads and unloads' '
	"$SHIRUDO_BIN" upatch load "$LIFECYCLE" --no-precheck >/dev/null 2>&1 &&
	test -e "$LIFECYCLE_PIN" &&
	"$SHIRUDO_BIN" upatch unload "$LIFECYCLE_UNLOAD" --no-precheck \
		>/dev/null 2>&1 &&
	test ! -e "$LIFECYCLE_PIN"
'

test_expect_success 'prebuilt marker fixture exposes kernel source metadata' '
	"$SHIRUDO_BIN" upatch load "$MARKER" --no-precheck >/dev/null 2>&1 &&
	"$SHIRUDO_BIN" upatch get shirudo-test-marker 2>/dev/null |
		grep -q shirudo_test_marker &&
	"$SHIRUDO_BIN" upatch unload "$MARKER_UNLOAD" --no-precheck \
		>/dev/null 2>&1
'

test_expect_success 'foreign-signed prebuilt fixture is rejected' '
	"$SHIRUDO_BIN" upatch load "$FOREIGN" --no-precheck --report=- \
		>"$WORK/foreign.json" 2>/dev/null || true
	res=$(report_field result <"$WORK/foreign.json") &&
	cat=$(report_field category <"$WORK/foreign.json") &&
	[ "$res" = failed ] &&
	{ [ "$cat" = keyring_missing ] || [ "$cat" = signature_rejected ]; }
'

test_expect_success 'valid non-shirudo keyring fixture is denied' '
	out=$(./helper/test-signed-load "$OWN" "$OWN_CERT") &&
	[ "$out" = "errno=$(foreign_keyring_errno)" ]
'

test_expect_success 'prebuilt map fixture exports mixed log and metric maps' '
	"$SHIRUDO_BIN" upatch load "$MAP_EXPORT" --no-precheck >/dev/null 2>&1 &&
	"$SHIRUDO_BIN" upatch map --all --json="$WORK/maps.ndjson" &&
	python3 - "$WORK/maps.ndjson" <<'PY'
import json
import sys

records = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
log = next(record for record in records
           if isinstance(record, dict) and record.get("map") == "first")
metric = next(record for record in records if isinstance(record, list))
assert log["upatch"] == "shirudo-test-map-export", log
assert log["schema"] == 1, log
assert metric[0]["name"] == "shirudo.map_export.second", metric
PY
'

test_done
