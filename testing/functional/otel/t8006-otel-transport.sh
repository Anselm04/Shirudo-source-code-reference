#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t8006 -- where an OTLP export goes and how, as the environment says: the
# endpoint, header, protocol, compression and timeout variables, a
# signal-specific one over the generic one, an empty one as unset, and the
# default; what is refused before any request is sent; and the bound on a
# collector's response. TLS material is t8105's, on the target, where a
# collector can offer the hybrid ML-KEM groups.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

H=$PWD/helper/test-otel-map
M=$PWD/helper
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
[ -x "$H" ] || test_skip_all "test-otel-map helper not built"
for v in $(env | sed -n 's/^\(OTEL_EXPORTER_OTLP_[A-Z_]*\)=.*/\1/p'); do
	unset "$v"
done
W=$(mktemp -d) || exit 1
trap 'rm -rf "$W"' EXIT
cd "$W" || exit 1

# Start the OTLP mock in mode $1; it listens on $port as $server.
mock() {
	rm -f otel.port otel.body otel.meta
	python3 "$M/otel-mock.py" "$1" otel.port otel.body otel.meta &
	server=$!
	i=0
	while [ ! -s otel.port ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep .02
	done
	port=$(cat otel.port)
}

# The field $1 of the request the mock saw, headers.<name> for a header.
meta() {
	python3 -c '
import json, sys
value = json.load(open("otel.meta"))
for part in sys.argv[1].split(".", 1):
    value = value.get(part, "") if isinstance(value, dict) else ""
print(value)' "$1"
}

# A log export with the environment assignments $@ fails, and the mock
# it would have reached saw no request.
refused() {
	mock success
	rc=0
	env OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:$port" "$@" \
		"$H" send-log-env 0 2>/dev/null || rc=$?
	kill "$server" 2>/dev/null || true
	wait "$server" 2>/dev/null || true
	[ "$rc" != 0 ] && [ ! -e otel.meta ] || {
		echo "not refused: $*"
		return 1
	}
}

test_expect_success 'the generic endpoint gets the signal path, a signal one is used as given' '
	mock success &&
	OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:$port/base?fleet=eu" \
		"$H" send-log-env 0 && wait "$server" &&
	[ "$(meta path)" = "/base/v1/logs?fleet=eu" ] &&
	mock success &&
	OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:$port/base/" \
		"$H" send-metric-env && wait "$server" &&
	[ "$(meta path)" = /base/v1/metrics ] &&
	mock success &&
	OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:1/generic \
	OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="http://127.0.0.1:$port/ingest" \
		"$H" send-log-env 0 && wait "$server" &&
	[ "$(meta path)" = /ingest ] &&
	mock success &&
	OTEL_EXPORTER_OTLP_METRICS_ENDPOINT="http://127.0.0.1:$port/ingest/m" \
		"$H" send-metric-env && wait "$server" &&
	[ "$(meta path)" = /ingest/m ]
'

test_expect_success 'an empty variable is unset, and one signal leaves the other alone' '
	mock success &&
	OTEL_EXPORTER_OTLP_LOGS_ENDPOINT= \
	OTEL_EXPORTER_OTLP_LOGS_HEADERS= OTEL_EXPORTER_OTLP_HEADERS=X-Fleet=eu \
	OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:$port" \
		"$H" send-log-env 0 && wait "$server" &&
	[ "$(meta path)" = /v1/logs ] && [ "$(meta headers.x-fleet)" = eu ] &&
	mock success &&
	OTEL_EXPORTER_OTLP_LOGS_ENDPOINT=http://127.0.0.1:1/v1/logs \
	OTEL_EXPORTER_OTLP_LOGS_HEADERS=X-Logs=1 \
	OTEL_EXPORTER_OTLP_LOGS_COMPRESSION=gzip \
	OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:$port" \
		"$H" send-metric-env && wait "$server" &&
	[ "$(meta path)" = /v1/metrics ] &&
	[ -z "$(meta headers.x-logs)" ] && [ -z "$(meta content_encoding)" ]
'

if python3 -c 'import socket; socket.socket().bind(("127.0.0.1", 4318))' 2>/dev/null; then
	test_expect_success 'without any endpoint the export goes to localhost:4318' '
		export SHIRUDO_TEST_OTEL_PORT=4318 &&
		mock success &&
		"$H" send-log-env 0 && wait "$server" &&
		[ "$(meta path)" = /v1/logs ] &&
		[ "$(meta headers.host)" = localhost:4318 ]
	'
else
	echo "# SKIP port 4318 is taken, the default endpoint is not tried"
fi

test_expect_success 'signal headers replace the generic ones, trimmed and decoded' '
	mock success &&
	OTEL_EXPORTER_OTLP_HEADERS="X-Generic=1,Authorization=Bearer%20generic" \
	OTEL_EXPORTER_OTLP_LOGS_HEADERS=" X-Signal = a%2Cb,Authorization=Bearer%20specific" \
	OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:$port" \
		"$H" send-log-env 0 && wait "$server" &&
	[ "$(meta headers.x-signal)" = "a,b" ] &&
	[ "$(meta headers.authorization)" = "Bearer specific" ] &&
	[ -z "$(meta headers.x-generic)" ] &&
	[ "$(meta headers.content-type)" = application/json ] &&
	[ "$(meta headers.user-agent)" = "shirudo OTel-OTLP-Exporter-C/1" ]
'

test_expect_success 'malformed, reserved and oversized headers are refused before any request' '
	for h in X-No-Value =value X:Colon=v X-Bad=%zz X-Bad=%4 X-Bad=a%0Db \
		 Content-Type=text/plain Content-Encoding=br Content-Length=1 \
		 Host=collector User-Agent=other; do
		refused OTEL_EXPORTER_OTLP_LOGS_HEADERS="$h" || return 1
	done &&
	pad=$(python3 -c "print(\"x\" * (16384 - len(\"X-Big=\")))") &&
	refused OTEL_EXPORTER_OTLP_HEADERS="X-Big=${pad}x" &&
	mock success &&
	OTEL_EXPORTER_OTLP_HEADERS="X-Big=$pad" \
	OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:$port" \
		"$H" send-log-env 0 && wait "$server" &&
	[ "$(meta headers.x-big)" = "$pad" ]
'

test_expect_success 'only http/json is spoken' '
	refused OTEL_EXPORTER_OTLP_PROTOCOL=grpc &&
	refused OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf &&
	refused OTEL_EXPORTER_OTLP_LOGS_PROTOCOL=grpc \
		OTEL_EXPORTER_OTLP_PROTOCOL=http/json &&
	mock success &&
	OTEL_EXPORTER_OTLP_PROTOCOL=http/json \
	OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:$port" \
		"$H" send-log-env 0 && wait "$server"
'

test_expect_success 'compression is gzip or none, the signal one first' '
	refused OTEL_EXPORTER_OTLP_COMPRESSION=br &&
	refused OTEL_EXPORTER_OTLP_LOGS_COMPRESSION=deflate &&
	mock success &&
	OTEL_EXPORTER_OTLP_COMPRESSION=gzip \
	OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:$port" \
		"$H" send-log-env 0 && wait "$server" &&
	[ "$(meta content_encoding)" = gzip ] &&
	mock success &&
	OTEL_EXPORTER_OTLP_COMPRESSION=gzip OTEL_EXPORTER_OTLP_LOGS_COMPRESSION=none \
	OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:$port" \
		"$H" send-log-env 0 && wait "$server" &&
	[ -z "$(meta content_encoding)" ]
'

test_expect_success 'an attempt timeout is 1 to 120000 ms, the signal one first' '
	for t in 0 120001 -1 10s " 5"; do
		refused OTEL_EXPORTER_OTLP_TIMEOUT="$t" || return 1
	done &&
	refused OTEL_EXPORTER_OTLP_LOGS_TIMEOUT=0 OTEL_EXPORTER_OTLP_TIMEOUT=5000 &&
	mock success &&
	OTEL_EXPORTER_OTLP_TIMEOUT=120000 \
	OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:$port" \
		"$H" send-log-env 0 && wait "$server" &&
	mock timeout &&
	OTEL_EXPORTER_OTLP_TIMEOUT=100 OTEL_EXPORTER_OTLP_LOGS_TIMEOUT=5000 \
	OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:$port" \
		"$H" send-log-env 0 && wait "$server" &&
	mock timeout &&
	! OTEL_EXPORTER_OTLP_TIMEOUT=5000 OTEL_EXPORTER_OTLP_LOGS_TIMEOUT=100 \
	OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:$port" \
		"$H" send-log-env 0 2>/dev/null && wait "$server"
'

test_expect_success 'a client certificate needs its key, and the key its certificate' '
	refused OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE=client.pem &&
	refused OTEL_EXPORTER_OTLP_LOGS_CLIENT_KEY=client.key
'

test_expect_success 'a collector response is read up to 64 KiB less one byte' '
	mock big-ok &&
	"$H" send-log "http://127.0.0.1:$port" 2 && wait "$server" &&
	mock big-over &&
	! "$H" send-log "http://127.0.0.1:$port" 2 2>/dev/null && wait "$server" &&
	[ "$(meta attempts)" = 1 ]
'

test_done
