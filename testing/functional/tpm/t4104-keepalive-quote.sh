#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t4104 -- the quote a keepalive carries, as shirudo-quote-check reads
# it: the attestation key of shirudo attest quotes the SHA-256 of the
# body, signs as that key under the endorsement hierarchy, and orders
# its quotes by the TPM clock; another body does not match it.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
QUOTE_CHECK=helper/shirudo-quote-check
[ -x "$QUOTE_CHECK" ] || test_skip_all "shirudo-quote-check is not built"
"$SHIRUDO_BIN" image update "$SHIRUDO_TEST_KEY_FIXTURES/config-otel" \
	>/dev/null 2>&1 || test_skip_all "cannot activate the config-otel image"
export SHIRUDO_TEST_OTEL_PORT=5444
NONCE=0102030405060708090a0b0c0d0e0f10
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

# Splits a received record into its body, $W/$1.body, and the row of
# shirudo-quote-check for it, $W/$1.row; with a third argument the row
# names the hash of that file instead of the body's.
cat >"$W/row.py" <<'PY'
import hashlib, json, sys

record = json.load(open(sys.argv[1]))["resourceLogs"][0]["scopeLogs"][0][
    "logRecords"][0]
body = record["body"]["stringValue"].encode()
open(sys.argv[2], "wb").write(body)
fields = dict(f.split("=", 1) for f in
              record["attributes"][0]["value"]["stringValue"].split(";"))
hashed = open(sys.argv[4], "rb").read() if len(sys.argv) > 4 else body
row = [fields["attest"], fields["sig"], fields["ak"],
       hashlib.sha256(hashed).hexdigest()]
open(sys.argv[3], "w").write("\t".join(row) + "\n")
PY

# The quoted data and the signer of a TPMS_ATTEST against the body and
# the attestation key of a row.
cat >"$W/attest.py" <<'PY'
import base64, hashlib, struct, sys

attest_b64, _, ak_b64, _ = open(sys.argv[1]).read().rstrip("\n").split("\t")
body = open(sys.argv[2], "rb").read()
attest = base64.b64decode(attest_b64)
ak_name = b"\x00\x0b" + hashlib.sha256(base64.b64decode(ak_b64)).digest()
qualified = b"\x00\x0b" + hashlib.sha256(
    struct.pack(">I", 0x4000000B) + ak_name).digest()
magic, kind = struct.unpack(">IH", attest[:6])
assert (magic, kind) == (0xFF544347, 0x8018), (hex(magic), hex(kind))
off = 6
size, = struct.unpack(">H", attest[off:off + 2])
signer = attest[off + 2:off + 2 + size]
off += 2 + size
size, = struct.unpack(">H", attest[off:off + 2])
extra = attest[off + 2:off + 2 + size]
assert signer == qualified, (signer.hex(), qualified.hex())
assert extra == hashlib.sha256(body).digest(), extra.hex()
print(ak_name.hex())
PY

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
	"$SHIRUDO_BIN" status --otel >/dev/null || return 1
	wait "$(cat "$W/sink.pid")" || return 1
	rm -f "$W/sink.pid" &&
	python3 "$W/row.py" "$W/$1.json" "$W/$1.body" "$W/$1.row"
}

# A key of the checker's line for row $1.
checked() {
	python3 -c '
import json, sys
print(json.loads(open(sys.argv[1]).read())[sys.argv[2]])
' "$W/$1.out" "$2"
}

test_expect_success 'the checker accepts a keepalive quote of its body' '
	send_keepalive one &&
	"$QUOTE_CHECK" <"$W/one.row" >"$W/one.out" &&
	[ "$(checked one ok)" = 1 ] &&
	python3 "$W/attest.py" "$W/one.row" "$W/one.body" >"$W/one.name" &&
	[ "$(checked one ak_name)" = "$(cat "$W/one.name")" ]
'

test_expect_success 'the keepalive key is the attestation key of shirudo attest' '
	"$SHIRUDO_BIN" attest --nonce="$NONCE" --output="$W/evidence.json" &&
	python3 -c "
import json, sys
print(json.load(open(sys.argv[1]))[\"ak\"][\"name\"])
" "$W/evidence.json" >"$W/attest.name" &&
	[ "$(cat "$W/attest.name")" = "$(checked one ak_name)" ]
'

test_expect_success 'a later keepalive has a later TPM clock' '
	send_keepalive two &&
	"$QUOTE_CHECK" <"$W/two.row" >"$W/two.out" &&
	[ "$(checked two ok)" = 1 ] &&
	[ "$(checked two ak_name)" = "$(checked one ak_name)" ] &&
	python3 -c "
import json, sys
one, two = (json.load(open(p)) for p in sys.argv[1:3])
assert (two[\"reset_count\"], two[\"clock\"]) > \
	(one[\"reset_count\"], one[\"clock\"]), (one, two)
" "$W/one.out" "$W/two.out"
'

test_expect_success 'a body altered by one byte does not match the quote' '
	python3 -c "
import sys
body = bytearray(open(sys.argv[1], \"rb\").read())
body[-2] ^= 1
open(sys.argv[2], \"wb\").write(body)
" "$W/one.body" "$W/altered.body" &&
	python3 "$W/row.py" "$W/one.json" "$W/one.body" "$W/altered.row" \
		"$W/altered.body" &&
	"$QUOTE_CHECK" <"$W/altered.row" >"$W/altered.out" &&
	[ "$(checked altered ok)" = 0 ] &&
	[ "$(checked altered reason)" = body_mismatch ]
'

test_done
