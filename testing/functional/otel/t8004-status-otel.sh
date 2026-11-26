#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh

S=../shirudo
H=helper/test-otel-map

# No TPM answers here: the keepalive cannot be quoted.
export SHIRUDO_TPM_TCTI=device:/nonexistent/tpm

# A sink on an ephemeral port; its pid is in $work/sink.pid.
sink() {
	rm -f "$work/port"
	python3 helper/otel-mock.py success "$work/port" "$work/body" \
		"$work/meta" &
	echo "$!" >"$work/sink.pid"
	i=0
	while test ! -s "$work/port" && test "$i" -lt 100; do
		sleep .02
		i=$((i + 1))
	done
	test -s "$work/port"
}

test_expect_success 'status --keepalive prints the body with its keys in order' '
	work=$(mktemp -d) &&
	"$S" status --keepalive >"$work/body" 2>"$work/stderr" &&
	python3 - "$work/body" <<"PY" &&
import json, sys

KEYS = ["schema", "boot_id", "version_id", "config_root", "kernel_release",
        "image_id", "image_version", "image_root", "verdict", "cond",
        "flags", "tamper", "integrity", "tree_id", "generation",
        "base_seq", "last_seq", "base_root", "projection_root", "mask",
        "set_sha256", "count", "not_ok"]
text = open(sys.argv[1]).read()
assert text.endswith("}\n") and text.count("\n") == 1, text
pairs = json.loads(text, object_pairs_hook=list)
assert [k for k, _ in pairs] == KEYS, pairs
assert dict(pairs)["schema"] == "shirudo.keepalive/1"
PY
	rm -rf "$work"
'

test_expect_success 'status --otel without a TPM sends nothing and fails' '
	work=$(mktemp -d) &&
	sink &&
	port=$(cat "$work/port") &&
	! OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="http://127.0.0.1:$port/v1/logs" \
		"$S" status --otel >"$work/stdout" 2>"$work/stderr" &&
	test ! -s "$work/stdout" &&
	grep -q "nothing is sent" "$work/stderr" &&
	test ! -e "$work/body" &&
	kill "$(cat "$work/sink.pid")" &&
	rm -rf "$work"
'

test_expect_success 'status --json --otel prints the report when the keepalive fails' '
	work=$(mktemp -d) &&
	sink &&
	port=$(cat "$work/port") &&
	! OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="http://127.0.0.1:$port/v1/logs" \
		"$S" status --json --otel >"$work/stdout" 2>"$work/stderr" &&
	test ! -e "$work/body" &&
	kill "$(cat "$work/sink.pid")" &&
	python3 - "$work/stdout" <<"PY" &&
import json
import sys

doc = json.load(open(sys.argv[1]))
assert doc["schema"] == 1
assert "status" in doc
assert "tpm" in doc
assert "tamper_attempts" in doc
PY
	rm -rf "$work"
'

test_expect_success 'status --otel without an endpoint does not send' '
	work=$(mktemp -d)
	env -u OTEL_EXPORTER_OTLP_LOGS_ENDPOINT \
		-u OTEL_EXPORTER_OTLP_ENDPOINT \
		"$S" status --json --otel >"$work/stdout" 2>"$work/stderr" &&
	python3 - "$work/stdout" <<"PY"
import json
import sys

doc = json.load(open(sys.argv[1]))
assert doc["schema"] == 1
assert "status" in doc
PY
	rm -rf "$work"
'

test_expect_success 'status --json --include-system includes kernel config' '
	work=$(mktemp -d) &&
	"$S" status --json --include-system >"$work/status.json" 2>"$work/stderr" &&
	cat >"$work/check.py" <<"PY" &&
import json
import os
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
system = doc["system"]
assert isinstance(system["kernel_build_id"], str)
assert all(c in "0123456789abcdef" for c in system["kernel_build_id"])
config = system["kernel_config"]
assert isinstance(config, dict)
assert all(key.startswith("CONFIG_") for key in config)
assert list(config) == sorted(config)

path = "/boot/config-" + system["kernel_release"]
if os.path.isfile(path):
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.rstrip("\r\n")
        if line.startswith("# CONFIG_") and line.endswith(" is not set"):
            key = line[2:].split(" is not set", 1)[0]
            assert config[key] == "n"
            continue
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            if len(value) >= 2 and value[0] == value[-1] == "\"":
                value = value[1:-1]
            assert config[key] == value
            break
    else:
        raise AssertionError("kernel config has no CONFIG_ entries")
PY
	python3 -I "$work/check.py" "$work/status.json" &&
	rm -rf "$work"
'

test_expect_success 'status --include-system prints kernel config' '
	work=$(mktemp -d) &&
	"$S" status --include-system >"$work/status" 2>"$work/stderr" &&
	grep -Eq "^  Kernel build ID: +([0-9a-f]+)?$" "$work/status" &&
	"$S" status --json --include-system 2>/dev/null |
		python3 -c "import json, sys; sys.exit(0 if \"kernel_config\" in json.load(sys.stdin)[\"system\"] else 1)" &&
	rm -rf "$work"
'

test_expect_success 'a keepalive record carries its body as a string and one quote attribute' '
	work=$(mktemp -d) || return 1
	quote="attest=/1RDR4AY;sig=ABgACwAg;ak=ACMACwAE" &&
	printf "%s\303\251%s" \
		"{\"schema\":\"shirudo.keepalive/1\",\"image_id\":\"a\\\\b \\u00e9 " \
		"\",\"tamper\":[0,1],\"mask\":null}" >"$work/input" || return 1
	for verdict in ok degraded init-pending reboot-pending lsm-off tampered
	do
		python3 helper/otel-mock.py success "$work/port" "$work/body" \
			"$work/meta" &
		server=$!
		trap "kill $server 2>/dev/null || true; wait $server 2>/dev/null || true; rm -rf $work" EXIT
		i=0
		while test ! -s "$work/port" && test "$i" -lt 100; do
			sleep .02
			i=$((i + 1))
		done
		port=$(cat "$work/port") &&
		"$H" send-keepalive "http://127.0.0.1:$port" "$verdict" \
			"$work/input" "$quote" &&
		wait "$server" &&
		python3 - "$verdict" "$work/body" "$work/meta" "$work/input" \
			"$quote" <<'\''PY'\'' || return 1
import json, socket, sys
verdict, quote = sys.argv[1], sys.argv[5]
sent = open(sys.argv[4], "rb").read()
assert b"\\u00e9 \xc3\xa9" in sent and b"a\\\\b" in sent, sent
assert json.load(open(sys.argv[3]))["path"] == "/v1/logs"
rl = json.load(open(sys.argv[2]))["resourceLogs"][0]
resource = {item["key"]: item["value"] for item in rl["resource"]["attributes"]}
assert resource == {"service.name": {"stringValue": "shirudo"},
                    "service.version": {"stringValue": "test-1"},
                    "host.name": {"stringValue": socket.gethostname()}}, resource
assert rl["scopeLogs"][0]["scope"] == {"name": "shirudo.keepalive",
                                       "version": "test-1"}
record = rl["scopeLogs"][0]["logRecords"][0]
expected = {"ok": (9, "INFO"), "degraded": (13, "WARN"),
            "init-pending": (13, "WARN"), "reboot-pending": (13, "WARN"),
            "lsm-off": (17, "ERROR"),
            "tampered": (17, "ERROR")}[verdict]
assert (record["severityNumber"], record["severityText"]) == expected
assert record["eventName"] == "shirudo.keepalive"
assert record["timeUnixNano"].isdigit()
assert list(record["body"]) == ["stringValue"], record["body"]
assert record["body"]["stringValue"].encode() == sent, record["body"]
assert record["attributes"] == [
    {"key": "shirudo.quote", "value": {"stringValue": quote}}
], record["attributes"]
PY
		rm -f "$work/port" "$work/body" "$work/meta" || return 1
	done
	rm -rf "$work"
'

test_expect_success 'a keepalive body JSON cannot carry unchanged is not sent' '
	work=$(mktemp -d) || return 1
	printf "{\"image_id\":\"\\377\"}" >"$work/latin1" &&
	printf "{\"image_id\":\"\\000\"}" >"$work/nul" || return 1
	for input in latin1 nul
	do
		python3 helper/otel-mock.py success "$work/port" "$work/body" \
			"$work/meta" &
		server=$!
		trap "kill $server 2>/dev/null || true; wait $server 2>/dev/null || true; rm -rf $work" EXIT
		i=0
		while test ! -s "$work/port" && test "$i" -lt 100; do
			sleep .02
			i=$((i + 1))
		done
		port=$(cat "$work/port") &&
		! "$H" send-keepalive "http://127.0.0.1:$port" ok \
			"$work/$input" quote &&
		test ! -e "$work/body" || return 1
		kill "$server" && { wait "$server" || true; } &&
		rm -f "$work/port" || return 1
	done
	rm -rf "$work"
'

test_done
