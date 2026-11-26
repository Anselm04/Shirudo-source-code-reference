#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t8104 -- what the signed config sets for `upatch map --all` and what
# overrides it: map_export.otel_endpoint and map_export.tenant_id win
# over the OTEL_EXPORTER_OTLP_* variables, and --otel-endpoint and
# --tenant-id over them. An export that fails, the collector down, fails
# that run of the map-export service, the timer runs it again, and the
# interval the failed run drained is not sent again: the next one holds
# only what was collected since. The serialized-metric fixture counts 10
# packets once after a load.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v systemctl >/dev/null 2>&1 || test_skip_all "no systemctl"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-serialized-metric
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME"
CONFIG_PORT=5444
W=$(mktemp -d)
[ -s "$LOAD" ] && [ -s "$UNLOAD" ] || test_skip_all "missing serialized metric fixture"
[ ! -e "$PIN" ] || test_skip_all "$NAME is loaded"
systemctl cat shirudo-map-export.timer >/dev/null 2>&1 ||
	test_skip_all "map-export timer is not installed"
"$SHIRUDO_BIN" image update "$SHIRUDO_TEST_KEY_FIXTURES/config-otel" \
	>/dev/null 2>&1 || test_skip_all "cannot activate the config-otel image"

# The sinks, started in the subshells the test bodies run in, by their
# pid files.
stop_sinks() {
	for p in "$W"/*.pid; do
		[ -e "$p" ] || continue
		kill "$(cat "$p")" 2>/dev/null || true
		rm -f "$p"
	done
}

# Under the library's errexit a failing step would end the cleanup.
cleanup() {
	systemctl stop shirudo-map-export.timer >/dev/null 2>&1 || true
	systemctl stop shirudo-map-export.service >/dev/null 2>&1 || true
	systemctl reset-failed shirudo-map-export.service >/dev/null 2>&1 || true
	stop_sinks
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	if [ "$TIMER_WAS_ACTIVE" = 1 ]; then
		systemctl start shirudo-map-export.timer >/dev/null 2>&1 || true
	fi
	rm -rf "$W"
}
TIMER_WAS_ACTIVE=0
systemctl is-active --quiet shirudo-map-export.timer && TIMER_WAS_ACTIVE=1
trap cleanup EXIT
systemctl stop shirudo-map-export.timer >/dev/null 2>&1 || true
systemctl stop shirudo-map-export.service >/dev/null 2>&1 || true

cat >"$W/sink.py" <<'PY'
import http.server, json, pathlib, sys
port, port_file, out = int(sys.argv[1]), *map(pathlib.Path, sys.argv[2:4])
requests = []
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        requests.append({"path": self.path,
                         "tenant": self.headers.get("X-Tenant-ID", ""),
                         "body": body})
        out.write_text(json.dumps(requests))
        payload = b"{}"
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *args): pass
server = http.server.HTTPServer(("127.0.0.1", port), Handler)
port_file.write_text(str(server.server_port))
server.serve_forever()
PY

# Start a sink on port $1 (0 for any) recording into $W/$2.json; the port
# it got is in $W/$2.port.
sink() {
	rm -f "$W/$2.port" "$W/$2.json"
	python3 "$W/sink.py" "$1" "$W/$2.port" "$W/$2.json" &
	echo "$!" >"$W/$2.pid"
	i=0
	while [ ! -s "$W/$2.port" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep .05
	done
	[ -s "$W/$2.port" ]
}

# The requests sink $1 recorded: their paths and tenants, and the packet
# counts of the serialized metric they carry, one line per request.
seen() {
	python3 - "$W/$1.json" <<'PY'
import json, os, sys
if not os.path.exists(sys.argv[1]):
    sys.exit(0)
for r in json.load(open(sys.argv[1])):
    packets = ""
    for rm in r["body"].get("resourceMetrics", []):
        for sm in rm["scopeMetrics"]:
            for m in sm["metrics"]:
                if m["name"] == "shirudo.serialized.packets":
                    packets = m["sum"]["dataPoints"][0]["asInt"]
    print(r["path"], r["tenant"], packets)
PY
}

test_expect_success 'the config names the endpoint and tenant, over the environment' '
	sink "$CONFIG_PORT" config && sink 0 env &&
	env_url="http://127.0.0.1:$(cat "$W/env.port")" &&
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	OTEL_EXPORTER_OTLP_ENDPOINT="$env_url" \
	OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="$env_url/v1/logs" \
	OTEL_EXPORTER_OTLP_METRICS_ENDPOINT="$env_url/v1/metrics" \
	OTEL_EXPORTER_OTLP_HEADERS=X-Tenant-ID=tenant-env-1111 \
		"$SHIRUDO_BIN" upatch map --all >/dev/null &&
	seen config >"$W/config.seen" && seen env >"$W/env.seen" &&
	grep -qx "/v1/metrics tenant-config-0000 10" "$W/config.seen" &&
	grep -q "^/v1/logs tenant-config-0000" "$W/config.seen" &&
	[ "$(grep -vc " tenant-config-0000" "$W/config.seen")" = 0 ] &&
	[ ! -s "$W/env.seen" ]
'

test_expect_success 'the command line wins over the config' '
	sink 0 cli &&
	cli_url="http://127.0.0.1:$(cat "$W/cli.port")" &&
	"$SHIRUDO_BIN" upatch map --all --otel-endpoint="$cli_url" \
		--tenant-id=tenant-cli-2222 >/dev/null &&
	seen cli >"$W/cli.seen" && seen config >"$W/config.seen2" &&
	grep -qx "/v1/metrics tenant-cli-2222 0" "$W/cli.seen" &&
	grep -q "^/v1/logs tenant-cli-2222" "$W/cli.seen" &&
	[ "$(grep -vc " tenant-cli-2222" "$W/cli.seen")" = 0 ] &&
	cmp -s "$W/config.seen" "$W/config.seen2"
'

stop_sinks

test_expect_success 'with the collector down, a run of the service fails' '
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 &&
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	! systemctl start shirudo-map-export.service 2>/dev/null &&
	[ "$(systemctl show -p Result --value shirudo-map-export.service)" = exit-code ]
'

test_expect_success 'the timer runs it again, without the interval the failed run drained' '
	sink "$CONFIG_PORT" timer &&
	systemctl start shirudo-map-export.timer &&
	i=0 &&
	until grep -q "^/v1/metrics " "$W/timer.seen" 2>/dev/null; do
		i=$((i + 1))
		[ "$i" -lt 60 ] || return 1
		sleep .5
		seen timer >"$W/timer.seen"
	done &&
	systemctl stop shirudo-map-export.timer &&
	grep -qx "/v1/metrics tenant-config-0000 0" "$W/timer.seen" || {
		cat "$W/timer.seen"
		false
	}
'

test_done
