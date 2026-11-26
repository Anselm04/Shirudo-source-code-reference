#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7010 -- a registry that trickles a blob, a few bytes a second and so
# fast enough for the low-speed limit, cannot hold a transfer, and with
# it the config operation lock on a target, past its total deadline: a
# minute for a small package, where the blob would take five.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

SHIRUDO=${SHIRUDO:-../shirudo}
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
W=$(mktemp -d)
SERVER=
cleanup() {
	[ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || :
	rm -rf "$W"
}
trap cleanup EXIT

cat >"$W/registry.py" <<'PY'
import hashlib, http.server, json, sys, time

SIZE = 1000
DIGEST = "sha256:" + hashlib.sha256(b"\0" * SIZE).hexdigest()
MANIFEST = json.dumps({
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "layers": [{"mediaType": "application/vnd.shirudo.bpm.package.v1+gzip",
                "digest": DIGEST, "size": SIZE}],
}).encode()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        if "/manifests/" in self.path:
            self.send_response(200)
            self.send_header("Content-Type",
                             "application/vnd.oci.image.manifest.v1+json")
            self.send_header("Content-Length", str(len(MANIFEST)))
            self.end_headers()
            self.wfile.write(MANIFEST)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(SIZE))
        self.end_headers()
        try:
            for _ in range(SIZE // 3):
                self.wfile.write(b"\0\0\0")
                self.wfile.flush()
                time.sleep(1)
        except OSError:
            pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(sys.argv[1], "w") as f:
    f.write(str(server.server_address[1]))
server.serve_forever()
PY
python3 "$W/registry.py" "$W/port" &
SERVER=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
	[ -s "$W/port" ] && break
	sleep 0.5
done
[ -s "$W/port" ] || test_skip_all "the trickling registry did not start"
PORT=$(cat "$W/port")

BIN=$(cd "$(dirname "$SHIRUDO")" && pwd)/$(basename "$SHIRUDO")

test_expect_success 'a trickled package download stops at its deadline' '
	start=$(date +%s) &&
	! (cd "$W" && BPM_OCI_SCHEME=http "$BIN" bpm pull \
		"oci://127.0.0.1:$PORT/ns/slow:1.0.0" >"$W/out" 2>&1) &&
	elapsed=$(($(date +%s) - start)) &&
	[ "$elapsed" -ge 50 ] &&
	[ "$elapsed" -lt 120 ]
'
test_done
