#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7011 -- bpm config update takes an oci:// base package only under the
# manifest digest the operator names: without --base-digest, and with a
# registry that serves another manifest under the tag, it refuses before
# it reads the package.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

REPO=$(cd .. && pwd)
S=$REPO/shirudo
SHB=$REPO/tools/shirudo-build/shirudo-build
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
[ -x "$S" ] || test_skip_all "shirudo not built"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built (make shirudo-build)"
W=$(mktemp -d)
SERVER=
cleanup() {
	[ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || :
	rm -rf "$W"
}
trap cleanup EXIT

cat >"$W/registry.py" <<'PY'
import http.server, json, sys

MANIFEST = json.dumps({
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "layers": [{"mediaType": "application/vnd.shirudo.bpm.package.v1+gzip",
                "digest": "sha256:" + "0" * 64, "size": 1}],
}).encode()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if "/manifests/" not in self.path:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type",
                         "application/vnd.oci.image.manifest.v1+json")
        self.send_header("Content-Length", str(len(MANIFEST)))
        self.end_headers()
        self.wfile.write(MANIFEST)


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
[ -s "$W/port" ] || test_skip_all "the registry did not start"
BASE="oci://127.0.0.1:$(cat "$W/port")/ns/base:1.0.0"
OTHER=sha256:$(printf '%064d' 1)
update() {
	(cd "$W" && BPM_OCI_SCHEME=http SHIRUDO_BUILD="$SHB" \
		"$S" bpm config update "$@" \
		--version 1.0.1 >"$W/out" 2>"$W/err")
}

test_expect_success 'an oci:// base needs the manifest digest' '
	! update --base-package "$BASE" &&
	grep -q "base-digest names the manifest of an oci:// base package" \
		"$W/err"
'
test_expect_success 'a local base takes none' '
	: >"$W/base.bee" &&
	! update --base-package "$W/base.bee" --base-digest "$OTHER" &&
	grep -q "base-digest names the manifest of an oci:// base package" \
		"$W/err"
'
test_expect_success 'a digest that is not sha256 hex is refused' '
	! update --base-package "$BASE" --base-digest sha256:ABC &&
	grep -q "is not sha256:<64 lowercase hex>" "$W/err"
'
test_expect_success 'another manifest under the tag is refused' '
	! update --base-package "$BASE" --base-digest "$OTHER" &&
	grep -q "serves manifest sha256:[0-9a-f]*, not $OTHER" "$W/err"
'
test_done
