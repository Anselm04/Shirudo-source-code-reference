#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
"""Small OCI Registry HTTP fixture for shirudo tests.

The fixture implements the OCI distribution GET surface needed by shirudo
tree synchronization and, with --writable, the push surface used by
`shirudo bpm push` and `shirudo bpm tree append` (monolithic blob uploads
and manifest puts).  Files are laid out as:

  ROOT/<repository>/manifests/<reference>
  ROOT/<repository>/blobs/<digest>

Every request is recorded as ``METHOD<TAB>PATH<TAB>STATUS`` when --log is
provided, so tests can assert that selectors caused only the expected
artifact requests.

A file beside a manifest or blob, named after it with ``.hold`` and
holding a number n, stops the n-th GET of it that comes while the file is
there: the fixture creates ``<name>.held`` and answers only once the hold
file is gone, so a test can stop a client at that request.
"""

import argparse
import hashlib
import http.server
import pathlib
import re
import secrets
import sys
import threading
import time
import urllib.parse

UPLOAD_RE = re.compile(r"/v2/(.+)/blobs/uploads/?")
UPLOAD_PUT_RE = re.compile(r"/v2/(.+)/blobs/uploads/([0-9a-f]+)")
MANIFEST_RE = re.compile(r"/v2/(.+)/manifests/([^/]+)")


class RegistryHandler(http.server.BaseHTTPRequestHandler):
    server_version = "shirudo-test-oci/1"

    def log_message(self, _format, *_args):
        pass

    def _record(self, status):
        log = self.server.request_log
        if log is not None:
            with log.open("a", encoding="utf-8") as stream:
                stream.write(f"{self.command}\t{self.path}\t{status}\n")

    def _reply(self, status, body=b"", content_type="text/plain", headers=()):
        self._record(status)
        self.send_response(status)
        if body:
            self.send_header("Content-Type", content_type)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _resolve(self, repository, kind, reference):
        relative = pathlib.Path(repository) / kind / reference
        root = self.server.registry_root.resolve()
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            return None
        return candidate

    def _file_for_request(self):
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        parts = path.split("/")
        if len(parts) < 5 or parts[1] != "v2":
            return None
        try:
            marker = next(i for i in range(2, len(parts))
                          if parts[i] in ("manifests", "blobs"))
        except StopIteration:
            return None
        repository = "/".join(parts[2:marker])
        reference = "/".join(parts[marker + 1:])
        if not repository or not reference:
            return None
        candidate = self._resolve(repository, parts[marker], reference)
        if candidate is None:
            return None
        return candidate, parts[marker]

    def _body(self):
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length) if length else b""

    def do_HEAD(self):
        self._serve()

    def do_GET(self):
        self._serve()

    def _serve(self):
        path = urllib.parse.urlsplit(self.path).path
        if path in ("/v2", "/v2/"):
            self._reply(200, b"", "application/json")
            return
        result = self._file_for_request()
        if result is None:
            self._reply(404)
            return
        candidate, kind = result
        self._hold(candidate)
        if not candidate.is_file():
            self._reply(404)
            return
        body = candidate.read_bytes()
        content_type = (
            "application/vnd.oci.image.manifest.v1+json"
            if kind == "manifests" else "application/octet-stream"
        )
        self._reply(200, body, content_type)

    def _hold(self, candidate):
        if self.command != "GET":
            return
        hold = candidate.with_name(candidate.name + ".hold")
        try:
            wanted = int(hold.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        with self.server.lock:
            count = self.server.held.get(candidate, 0) + 1
            self.server.held[candidate] = count
        if count != wanted:
            return
        candidate.with_name(candidate.name + ".held").touch()
        while hold.exists():
            time.sleep(0.05)

    def do_POST(self):
        self._body()
        if not self.server.writable:
            self._reply(405)
            return
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        match = UPLOAD_RE.fullmatch(path)
        if match is None:
            self._reply(404)
            return
        upload = secrets.token_hex(8)
        self.server.uploads[upload] = match.group(1)
        self._reply(202, headers=[
            ("Location", f"/v2/{match.group(1)}/blobs/uploads/{upload}")])

    def do_PUT(self):
        body = self._body()
        if not self.server.writable:
            self._reply(405)
            return
        split = urllib.parse.urlsplit(self.path)
        path = urllib.parse.unquote(split.path)
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        match = UPLOAD_PUT_RE.fullmatch(path)
        if match is not None:
            repository = self.server.uploads.pop(match.group(2), None)
            wanted = urllib.parse.parse_qs(split.query).get("digest", [None])[0]
            if repository != match.group(1) or wanted != digest:
                self._reply(400)
                return
            target = self._resolve(repository, "blobs", digest)
            if target is None:
                self._reply(400)
                return
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
            self._reply(201, headers=[("Docker-Content-Digest", digest)])
            return
        match = MANIFEST_RE.fullmatch(path)
        if match is not None:
            for reference in (match.group(2), digest):
                target = self._resolve(match.group(1), "manifests", reference)
                if target is None:
                    self._reply(400)
                    return
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(body)
            self._reply(201, headers=[("Docker-Content-Digest", digest)])
            return
        self._reply(404)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=pathlib.Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--log", type=pathlib.Path)
    parser.add_argument("--ready-file", type=pathlib.Path)
    parser.add_argument("--writable", action="store_true",
                        help="accept blob uploads and manifest puts")
    args = parser.parse_args()

    args.root.mkdir(parents=True, exist_ok=True)
    if args.log is not None:
        args.log.parent.mkdir(parents=True, exist_ok=True)
        args.log.write_text("", encoding="utf-8")
    if args.ready_file is not None:
        args.ready_file.unlink(missing_ok=True)

    server = http.server.ThreadingHTTPServer((args.host, args.port),
                                               RegistryHandler)
    server.registry_root = args.root
    server.request_log = args.log
    server.writable = args.writable
    server.uploads = {}
    server.held = {}
    server.lock = threading.Lock()
    if args.ready_file is not None:
        args.ready_file.touch()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
