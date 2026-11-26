#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7012 -- a registry that asks for a bearer token: the token its realm
# returns goes with the next request, the answer's own member and not
# one a string or a nested object names, and a realm that answers with an
# empty body fails the pull before any request carries a token, with
# registry credentials set as without. So does an answer that holds a
# NUL, which is no text to take a token from. A challenge whose scheme
# only starts with Bearer or Basic gets neither a token nor credentials.

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

# The realm of repository ns/<body> answers 200 with that body: "full"
# with a token, "empty" with nothing, "nul-behind" and "nul-ahead" with a
# token behind or ahead of a NUL, "quoted" and "nested" with a token
# behind a string and an object that name another. Repositories
# ns/glued-bearer and ns/glued-basic challenge with "Bearerx," and
# "Basicx". Each request is logged with the credentials it carried.
cat >"$W/registry.py" <<'PY'
import http.server, sys


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, status, body=b"", headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        auth = self.headers.get("Authorization", "none")
        with open(sys.argv[2], "a") as log:
            log.write("%s %s\n" % (self.path.split("?")[0], auth))
        port = self.server.server_address[1]
        if self.path.startswith("/token/full"):
            self.reply(200, b'{"token":"granted"}')
        elif self.path.startswith("/token/empty"):
            self.reply(200)
        elif self.path.startswith("/token/nul-behind"):
            self.reply(200, b'{"token":"first-token"}\0{"token":"other"}')
        elif self.path.startswith("/token/nul-ahead"):
            self.reply(200, b'\0{"token":"hidden-token"}')
        elif self.path.startswith("/token/quoted"):
            self.reply(200, b'{"note":"\\"token\\":\\"evil\\"","token":"good"}')
        elif self.path.startswith("/token/nested"):
            self.reply(200, b'{"data":{"token":"evil"},"token":"good"}')
        elif "/ns/glued-bearer/manifests/" in self.path:
            challenge = 'Bearerx,realm="http://127.0.0.1:%d/token/full"' % port
            self.reply(401, headers=[("WWW-Authenticate", challenge)])
        elif "/ns/glued-basic/manifests/" in self.path:
            self.reply(401, headers=[("WWW-Authenticate",
                                      'Basicx realm="registry"')])
        elif "/manifests/" in self.path:
            body = self.path.split("/")[3]
            challenge = ('Bearer realm="http://127.0.0.1:%d/token/%s",'
                         'service="registry",scope="repository:ns/%s:pull"'
                         % (port, body, body))
            self.reply(401, headers=[("WWW-Authenticate", challenge)])
        else:
            self.reply(404)


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(sys.argv[1], "w") as f:
    f.write(str(server.server_address[1]))
server.serve_forever()
PY
python3 "$W/registry.py" "$W/port" "$W/requests" &
SERVER=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
	[ -s "$W/port" ] && break
	sleep 0.5
done
[ -s "$W/port" ] || test_skip_all "the registry did not start"
PORT=$(cat "$W/port")

BIN=$(cd "$(dirname "$SHIRUDO")" && pwd)/$(basename "$SHIRUDO")

pull() {
	: >"$W/requests"
	(cd "$W" && BPM_OCI_SCHEME=http "$@" "$BIN" bpm pull \
		"oci://127.0.0.1:$PORT/ns/$PULL:1.0.0" >"$W/out" 2>&1)
}

test_expect_success 'the token the realm returns goes with the next request' '
	PULL=full &&
	! pull env &&
	grep -q "^/token/full none$" "$W/requests" &&
	grep -q "^/v2/ns/full/manifests/1.0.0 Bearer granted$" "$W/requests"
'

test_expect_success 'the token is the member of the answer, not one a string names' '
	PULL=quoted &&
	! pull env &&
	grep -q "^/v2/ns/quoted/manifests/1.0.0 Bearer good$" "$W/requests" &&
	! grep -q "Bearer evil" "$W/requests"
'

test_expect_success 'the token is the member of the answer, not a nested one' '
	PULL=nested &&
	! pull env &&
	grep -q "^/v2/ns/nested/manifests/1.0.0 Bearer good$" "$W/requests" &&
	! grep -q "Bearer evil" "$W/requests"
'

test_expect_success 'an empty token response fails before a token is sent' '
	PULL=empty &&
	! pull env &&
	grep -q "^/token/empty none$" "$W/requests" &&
	! grep -q "Bearer" "$W/requests"
'

test_expect_success 'an empty token response fails with credentials set too' '
	PULL=empty &&
	! pull env BPM_OCI_USERNAME=user BPM_OCI_PASSWORD=secret &&
	grep -q "^/token/empty Basic " "$W/requests" &&
	! grep -q "Bearer" "$W/requests"
'

test_expect_success 'an answer with a NUL behind a token gives none' '
	PULL=nul-behind &&
	! pull env BPM_OCI_USERNAME=user BPM_OCI_PASSWORD=secret &&
	grep -q "^/token/nul-behind Basic " "$W/requests" &&
	! grep -q "Bearer" "$W/requests"
'

test_expect_success 'an answer with a NUL ahead of a token gives none' '
	PULL=nul-ahead &&
	! pull env BPM_OCI_USERNAME=user BPM_OCI_PASSWORD=secret &&
	grep -q "^/token/nul-ahead Basic " "$W/requests" &&
	! grep -q "Bearer" "$W/requests"
'

test_expect_success 'a scheme that only starts with Bearer fetches no token' '
	PULL=glued-bearer &&
	! pull env &&
	grep -q "^/v2/ns/glued-bearer/manifests/1.0.0 none$" "$W/requests" &&
	! grep -q "^/token/" "$W/requests"
'

test_expect_success 'a scheme that only starts with Basic gets no credentials' '
	PULL=glued-basic &&
	! pull env BPM_OCI_USERNAME=user BPM_OCI_PASSWORD=secret &&
	grep -q "^/v2/ns/glued-basic/manifests/1.0.0 none$" "$W/requests" &&
	! grep -q "Basic" "$W/requests"
'

test_done
