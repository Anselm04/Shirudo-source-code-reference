#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t8106 -- status --otel on a target sends one OTLP log: the keepalive
# body as a string, the TPM quote of it as the one attribute and the
# severity of its verdict.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
"$SHIRUDO_BIN" image update "$SHIRUDO_TEST_KEY_FIXTURES/config-otel" \
	>/dev/null 2>&1 || test_skip_all "cannot activate the config-otel image"
export SHIRUDO_TEST_OTEL_PORT=5444
W=$(mktemp -d) || exit 1
TIMER_WAS_ACTIVE=0
systemctl is-active --quiet shirudo-keepalive.timer 2>/dev/null &&
	TIMER_WAS_ACTIVE=1

# Under the library's errexit a failing step would end the cleanup.
cleanup() {
	[ -s "$W/sink.pid" ] && kill "$(cat "$W/sink.pid")" 2>/dev/null || true
	if [ "$TIMER_WAS_ACTIVE" = 1 ]; then
		systemctl start shirudo-keepalive.timer >/dev/null 2>&1 || true
	fi
	rm -rf "$W"
}
trap cleanup EXIT
# The timer's own keepalive would reach the sink first.
systemctl stop shirudo-keepalive.timer >/dev/null 2>&1 || true
systemctl stop shirudo-keepalive.service >/dev/null 2>&1 || true

# status --otel against a sink, which keeps the request in $W/$1.json.
send_keepalive() {
	rm -f "$W/port"
	python3 helper/otel-mock.py success "$W/port" "$W/$1.json" \
		"$W/$1.meta" &
	echo "$!" >"$W/sink.pid"
	i=0
	while test ! -s "$W/port" && test "$i" -lt 100; do
		sleep .05
		i=$((i + 1))
	done
	"$SHIRUDO_BIN" status --otel >"$W/$1.stdout" || return 1
	wait "$(cat "$W/sink.pid")" || return 1
	rm -f "$W/sink.pid"
}

test_expect_success 'status --otel sends one record with a string body and its quote' '
	send_keepalive one &&
	test ! -s "$W/one.stdout" &&
	python3 - "$W/one.json" "$W/one.meta" <<"PY"
import base64, json, re, sys

KEYS = ["schema", "boot_id", "version_id", "config_root", "kernel_release",
        "image_id", "image_version", "image_root", "verdict", "cond",
        "flags", "tamper", "integrity", "tree_id", "generation",
        "base_seq", "last_seq", "base_root", "projection_root", "mask",
        "set_sha256", "count", "not_ok"]
SEVERITY = {"ok": (9, "INFO"), "degraded": (13, "WARN"),
            "init-pending": (13, "WARN"), "reboot-pending": (13, "WARN"),
            "tampered": (17, "ERROR"), "lsm-off": (17, "ERROR")}

meta = json.load(open(sys.argv[2]))
assert meta["attempts"] == 1 and meta["path"] == "/v1/logs", meta
rl = json.load(open(sys.argv[1]))["resourceLogs"]
assert len(rl) == 1 and len(rl[0]["scopeLogs"]) == 1
scope = rl[0]["scopeLogs"][0]
assert scope["scope"]["name"] == "shirudo.keepalive", scope["scope"]
assert len(scope["logRecords"]) == 1
record = scope["logRecords"][0]
assert record["eventName"] == "shirudo.keepalive"
assert list(record["body"]) == ["stringValue"], record["body"]
pairs = json.loads(record["body"]["stringValue"], object_pairs_hook=list)
assert [k for k, _ in pairs] == KEYS, pairs
body = dict(pairs)
assert body["schema"] == "shirudo.keepalive/1"
assert (record["severityNumber"], record["severityText"]) == \
    SEVERITY[body["verdict"]], (record, body["verdict"])
assert [a["key"] for a in record["attributes"]] == ["shirudo.quote"]
quote = record["attributes"][0]["value"]["stringValue"]
b64 = "([A-Za-z0-9+/]+={0,2})"
m = re.fullmatch("attest=%s;sig=%s;ak=%s" % (b64, b64, b64), quote)
assert m, quote
for field in m.groups():
    assert base64.b64encode(base64.b64decode(field, validate=True)) == \
        field.encode(), field
PY
'

test_done
