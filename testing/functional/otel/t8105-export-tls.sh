#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t8105 -- the TLS material of an export: the CA bundle a collector is
# verified with and the client certificate it gets, each the signal
# variable over the generic one, and S3 trusting AWS_CA_BUNDLE, never the
# collector's CA, nor the collector AWS_CA_BUNDLE. The collectors are the
# mocks behind a throwaway CA on the target, whose Python offers the
# hybrid ML-KEM groups the exporter requires; the exporter is
# test-otel-map's.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
python3 -c 'import ssl, sys; sys.exit(ssl.OPENSSL_VERSION_INFO < (3, 5))' ||
	test_skip_all "python3 cannot offer a hybrid ML-KEM group"
H=$PWD/helper/test-otel-map
M=$PWD/helper
[ -x "$H" ] || test_skip_all "test-otel-map helper not built"
for v in $(env | sed -n 's/^\(OTEL_EXPORTER_OTLP_[A-Z_]*\|AWS_[A-Z_0-9]*\)=.*/\1/p'); do
	unset "$v"
done
W=$(mktemp -d)
# A mock a failed test body left running, by its pid file.
cleanup() {
	[ ! -s "$W/m.pid" ] || kill "$(cat "$W/m.pid")" 2>/dev/null || true
	rm -rf "$W"
}
trap cleanup EXIT
cd "$W"

# A CA, the collector's certificate and two client certificates it
# issued, and a second CA that issued nothing here.
ca() {
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-keyout "$1.key" -out "$1.pem" -days 1 -subj "/CN=$1" 2>/dev/null
}
issue() {
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-keyout "$1.key" -out "$1.csr" -subj "/CN=$1" 2>/dev/null &&
	printf '%s\n' "$2" >"$1.ext" &&
	openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key \
		-CAcreateserial -out "$1.pem" -days 1 -extfile "$1.ext" 2>/dev/null
}
ca ca && ca other &&
	issue collector 'subjectAltName=IP:127.0.0.1' &&
	issue client-a 'extendedKeyUsage=clientAuth' &&
	issue client-b 'extendedKeyUsage=clientAuth' ||
	test_skip_all "openssl could not make the test certificates"

# Start mock $1 (otel or s3) in mode $2 with the TLS arguments to follow;
# it listens on $port.
mock() {
	kind=$1 mode=$2
	shift 2
	rm -f m.port m.body m.meta m.snapshot m.log
	if [ "$kind" = s3 ]; then
		python3 "$M/otel-s3-mock.py" "$mode" m.port m.snapshot m.log \
			m.meta "$@" &
	else
		python3 "$M/otel-mock.py" "$mode" m.port m.body m.meta "$@" &
	fi
	SERVER=$!
	echo "$SERVER" >m.pid
	i=0
	while [ ! -s m.port ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep .05
	done
	port=$(cat m.port)
}

# Wait for the mock to finish its exchange.
finished() {
	rc=0
	wait "$SERVER" || rc=$?
	rm -f m.pid
	return "$rc"
}

# Stop the mock, which must have seen no request when $1 is "none".
stop() {
	kill "$SERVER" 2>/dev/null || true
	wait "$SERVER" 2>/dev/null || true
	rm -f m.pid
	[ "${1:-}" != none ] || [ ! -e m.meta ]
}

field() {
	python3 -c '
import json, sys
print(json.load(open("m.meta")).get(sys.argv[1], ""))' "$1"
}

# A log export to the mock on $port, with the assignments $@.
send() {
	env OTEL_EXPORTER_OTLP_ENDPOINT="https://127.0.0.1:$port" "$@" \
		"$H" send-log-env 0 2>/dev/null
}

test_expect_success 'the signal CA wins over the generic one' '
	mock otel success collector.pem collector.key &&
	send OTEL_EXPORTER_OTLP_CERTIFICATE="$W/other.pem" \
		OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE="$W/ca.pem" &&
	finished &&
	mock otel success collector.pem collector.key &&
	! send OTEL_EXPORTER_OTLP_CERTIFICATE="$W/ca.pem" \
		OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE="$W/other.pem" &&
	stop none
'

test_expect_success 'the generic CA serves without a signal one, the system store without either' '
	mock otel success collector.pem collector.key &&
	send OTEL_EXPORTER_OTLP_CERTIFICATE="$W/ca.pem" &&
	finished &&
	mock otel success collector.pem collector.key &&
	! send &&
	stop none
'

test_expect_success 'a collector that asks for a client certificate gets the signal one' '
	mock otel success collector.pem collector.key ca.pem &&
	send OTEL_EXPORTER_OTLP_CERTIFICATE="$W/ca.pem" \
		OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE="$W/client-b.pem" \
		OTEL_EXPORTER_OTLP_CLIENT_KEY="$W/client-b.key" \
		OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE="$W/client-a.pem" \
		OTEL_EXPORTER_OTLP_LOGS_CLIENT_KEY="$W/client-a.key" &&
	finished &&
	[ "$(field client)" = client-a ] &&
	mock otel success collector.pem collector.key ca.pem &&
	send OTEL_EXPORTER_OTLP_CERTIFICATE="$W/ca.pem" \
		OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE="$W/client-b.pem" \
		OTEL_EXPORTER_OTLP_CLIENT_KEY="$W/client-b.key" &&
	finished &&
	[ "$(field client)" = client-b ]
'

test_expect_success 'and without one gets nothing through' '
	mock otel success collector.pem collector.key ca.pem &&
	! send OTEL_EXPORTER_OTLP_CERTIFICATE="$W/ca.pem" &&
	stop none
'

# An S3 export to the mock on $port, the collector at the same place,
# with the assignments $@.
s3() {
	env AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=secret \
		AWS_REGION=us-east-1 \
		OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="https://127.0.0.1:$port/v1/logs" \
		"$@" "$H" send-s3 "https://127.0.0.1:$port" 0 2>/dev/null
}

methods() {
	python3 -c '
import json, os
if os.path.exists("m.meta"):
    print(" ".join(r["method"] for r in json.load(open("m.meta"))["requests"]))'
}

test_expect_success 'S3 is verified with AWS_CA_BUNDLE, the collector with its own CA' '
	mock s3 success collector.pem collector.key &&
	s3 AWS_CA_BUNDLE="$W/ca.pem" \
		OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE="$W/ca.pem" &&
	finished &&
	[ "$(methods)" = "PUT POST" ] && [ -s m.snapshot ] && [ -s m.log ]
'

test_expect_success 'the collector CA does not verify S3' '
	mock s3 success collector.pem collector.key &&
	! s3 OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE="$W/ca.pem" &&
	stop none
'

test_expect_success 'nor AWS_CA_BUNDLE the collector' '
	mock s3 success collector.pem collector.key &&
	! s3 AWS_CA_BUNDLE="$W/ca.pem" &&
	stop &&
	[ "$(methods)" = PUT ] && [ -s m.snapshot ] && [ ! -e m.log ]
'

test_done
