#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7007 -- bpm tree append publishes the fixes of a Beefile's
# [upatches.tree] on an add, in byte order, after artifact and outside
# operation_digest; carries every earlier operation's fixes into the next
# generation unchanged; writes none on a delete; and refuses to carry a
# previous publication's fixes in a form bpm build would not write.
# Needs clang, shirudo-build, python3 and an OpenSSL >= 3.5 (ML-DSA).

cd "$(dirname "$0")/../.."
. ./test-lib.sh

S=../shirudo
SHB=../tools/shirudo-build/shirudo-build

command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
[ -x "$S" ] || test_skip_all "shirudo not built"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built (make shirudo-build)"
[ -e ../vendor/linux/vmlinux.h ] || test_skip_all "no vendor/linux/vmlinux.h (build the tree)"
openssl list -public-key-algorithms 2>/dev/null | grep -qi 'ML-DSA' ||
	test_skip_all "openssl without ML-DSA (needs OpenSSL >= 3.5)"

REPO=$(cd .. && pwd)
case "$SHB" in
/*) B="$SHB" ;;
*)  B="$REPO/${SHB#../}" ;;
esac
S="$REPO/shirudo"

WORK=$(mktemp -d)
SERVER_PID=
cleanup() {
	[ -z "$SERVER_PID" ] || kill "$SERVER_PID" 2>/dev/null || :
	rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

"$S" genkey --keys-dir "$WORK/keys" >/dev/null 2>&1 ||
	test_skip_all "genkey failed"

export SHIRUDO_BUILD="$B" BPM_OCI_SCHEME=http
export REGISTRY_AUTH_FILE="$WORK/absent-auth.json" NO_PROXY=127.0.0.1 no_proxy=127.0.0.1
unset BPM_OCI_CA_FILE BPM_OCI_USERNAME BPM_OCI_PASSWORD

# A package of one upatch named $1 with $2 as the rest of its tree entry.
# The package directory doubles as shirudo-build's working directory, so
# the vendored headers and vmlinux.h are reached through symlinks.
package() {
	mkdir -p "$WORK/$1" &&
	ln -s "$REPO/vendor" "$WORK/$1/vendor" &&
	ln -s "$REPO/bpf" "$WORK/$1/bpf" &&
	printf '// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause\n#include "vmlinux.h"\n#include <bpf/bpf_helpers.h>\n#include <bpf/bpf_tracing.h>\n\nchar _license[] SEC("license") = "Dual BSD/GPL";\n\nSEC("fentry/do_nanosleep")\nint BPF_PROG(%s_fn)\n{\n\treturn 0;\n}\n' \
		"$1" >"$WORK/$1/$1.bpf.c" &&
	printf '[package]\nname = "%s"\n\n[[upatches]]\nsource = "%s.bpf.c"\n\n[upatches.tree]\nid = "%s"\n%s' \
		"$1" "$1" "$1" "$2" >"$WORK/$1/Beefile" &&
	( cd "$WORK" && "$S" bpm build "$1" --version 1.0.0 \
		--keys-dir "$WORK/keys" ) >&2
}

test_expect_success 'bpm build packages an upatch with fixes and one without' '
	package t7007a "fixes = [\"B\", \"A\"]
" &&
	package t7007b "" &&
	test -s "$WORK/t7007a-1.0.0.bee" && test -s "$WORK/t7007b-1.0.0.bee"
'
[ -s "$WORK/t7007a-1.0.0.bee" ] && [ -s "$WORK/t7007b-1.0.0.bee" ] || test_done

PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
REG="$WORK/registry"
python3 ./helper/test-oci-registry.py --root "$REG" --port "$PORT" --writable \
	--log "$WORK/requests.log" --ready-file "$WORK/ready" &
SERVER_PID=$!
i=0
while [ ! -e "$WORK/ready" ]; do
	i=$((i + 1))
	[ "$i" -lt 100 ] || test_skip_all "registry fixture did not start"
	sleep .05
done
TREE="oci://127.0.0.1:$PORT/ns/tree"

# Append the package of $1 with the rest of the arguments, and keep the
# publication it leaves as $WORK/gen<generation>.json.
append() {
	pkg=$1
	shift
	"$S" bpm tree append "$WORK/$pkg-1.0.0.bee" "$TREE" --tree-id t7007a \
		--keys-dir "$WORK/keys" "$@" >/dev/null 2>"$WORK/append.err" &&
	python3 - "$REG/ns/tree" "$WORK" <<'PY'
import json, pathlib, sys
repo, work = map(pathlib.Path, sys.argv[1:3])
manifest = json.loads((repo / "manifests" / "stable").read_bytes())
layer = [l for l in manifest["layers"] if l["mediaType"].endswith("+json")][0]
body = (repo / "blobs" / layer["digest"]).read_bytes()
pub = json.loads(body)
(work / f"gen{pub['generation']}.json").write_bytes(body)
PY
}

# Check generation $1 with a Python body on pub, its parsed document, and
# digest(op), the operation digest recomputed from the five canonical keys.
check() {
	python3 -c '
import hashlib, json, sys
body = open(sys.argv[1], "rb").read()
pub = json.loads(body)
def digest(op):
    canonical = {k: op[k] for k in ("seq", "op", "id", "selector", "artifact")}
    text = json.dumps(canonical, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(text).hexdigest()
for op in pub["operations"]:
    assert op["operation_digest"] == digest(op), op
exec(sys.argv[2])
' "$WORK/gen$1.json" "$2"
}

test_expect_success 'an add carries its fixes in byte order after artifact' '
	append t7007a &&
	check 1 "
op = pub[\"operations\"][0]
assert op[\"op\"] == \"add\" and op[\"id\"] == \"t7007a\", op
assert op[\"fixes\"] == [\"A\", \"B\"], op
assert list(op) == [\"seq\", \"op\", \"id\", \"selector\", \"artifact\",
                    \"fixes\", \"operation_digest\"], list(op)
assert b\"\\\"artifact\\\":{\" in body and b\"},\\\"fixes\\\":[\\\"A\\\",\\\"B\\\"],\\\"operation_digest\\\":\" in body
"
'

test_expect_success 'operation_digest covers the five canonical keys, not fixes' '
	check 1 "
op = pub[\"operations\"][0]
six = {k: op[k] for k in (\"seq\", \"op\", \"id\", \"selector\", \"artifact\", \"fixes\")}
text = json.dumps(six, separators=(\",\", \":\")).encode()
assert op[\"operation_digest\"] == digest(op), op
assert op[\"operation_digest\"] != \"sha256:\" + hashlib.sha256(text).hexdigest(), op
"
'

test_expect_success 'an add without fixes writes no key, and earlier fixes carry over' '
	append t7007b &&
	check 2 "
first = json.load(open(sys.argv[1].replace(\"gen2\", \"gen1\")))[\"operations\"][0]
assert pub[\"operations\"][0] == first, pub
assert list(pub[\"operations\"][0]) == list(first), pub
op = pub[\"operations\"][1]
assert op[\"id\"] == \"t7007b\" and \"fixes\" not in op, op
"
'

test_expect_success 'a delete writes no fixes, though its Beefile names some' '
	append t7007a --op delete &&
	check 3 "
before = json.load(open(sys.argv[1].replace(\"gen3\", \"gen2\")))[\"operations\"]
assert pub[\"operations\"][:2] == before, pub
op = pub[\"operations\"][2]
assert op[\"op\"] == \"delete\" and op[\"id\"] == \"t7007a\", op
assert \"fixes\" not in op, op
" &&
	append t7007a &&
	check 4 "
assert pub[\"operations\"][0][\"fixes\"] == [\"A\", \"B\"], pub
assert \"fixes\" not in pub[\"operations\"][1], pub
assert \"fixes\" not in pub[\"operations\"][2], pub
assert pub[\"operations\"][3][\"fixes\"] == [\"A\", \"B\"], pub
"
'

# Sign $1, a document, with the operator key and make it the tree's
# stable publication.
publish_signed() {
	openssl cms -sign -binary -md sha512 -in "$1" \
		-signer "$WORK/keys/cert.der" -inkey "$WORK/keys/signing_key.pem" \
		-outform DER -out "$1.sig" -nosmimecap -nocerts -keyid &&
	python3 - "$REG/ns/tree" "$1" <<'PY'
import hashlib, json, pathlib, sys
repo, doc = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
layers = []
for path, media in ((doc, "application/vnd.shirudo.upatch.tree.v1+json"),
                    (doc.with_name(doc.name + ".sig"),
                     "application/vnd.shirudo.upatch.tree.signature.v1")):
    body = path.read_bytes()
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    (repo / "blobs" / digest).write_bytes(body)
    layers.append({"mediaType": media, "digest": digest, "size": len(body)})
manifest = {"schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactType": "application/vnd.shirudo.upatch.tree.v1",
            "config": {"mediaType": "application/vnd.oci.empty.v1+json",
                       "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                       "size": 2},
            "layers": layers}
(repo / "manifests" / "stable").write_bytes(
    json.dumps(manifest, separators=(",", ":")).encode())
PY
}

# Generation 4 with fixes $2 on its operation $1 (from 0), re-signed.
malformed() {
	python3 - "$WORK/gen4.json" "$1" "$2" "$WORK/bad.json" <<'PY'
import json, sys
pub = json.load(open(sys.argv[1]))
op = pub["operations"][int(sys.argv[2])]
fixes = json.loads(sys.argv[3])
if fixes is None:
    op.pop("fixes")
else:
    out = {}
    for key, value in op.items():
        if key == "operation_digest":
            out["fixes"] = fixes
        out[key] = value
    op.clear()
    op.update(out)
open(sys.argv[4], "wb").write(json.dumps(pub, separators=(",", ":")).encode())
PY
	publish_signed "$WORK/bad.json"
}

# $1 the operation, $2 the fixes, which tree append must refuse to carry.
refused() {
	malformed "$1" "$2" &&
	cp "$REG/ns/tree/manifests/stable" "$WORK/bad.manifest" &&
	! "$S" bpm tree append "$WORK/t7007b-1.0.0.bee" "$TREE" --tree-id t7007a \
		--keys-dir "$WORK/keys" >/dev/null 2>"$WORK/bad.err" &&
	grep -q "has a fixes list bpm tree append would not write" \
		"$WORK/bad.err" &&
	cmp -s "$WORK/bad.manifest" "$REG/ns/tree/manifests/stable"
}

test_expect_success 'tree append refuses to carry fixes it would not write' '
	refused 2 "[\"A\"]" &&
	refused 0 "[\"B\",\"A\"]" &&
	refused 0 "[\"A\",\"A\"]" &&
	refused 0 "[]" &&
	refused 0 "[\"\"]" &&
	refused 0 "[\"A/B\"]" &&
	refused 0 "[1]" &&
	refused 0 "\"A\"" &&
	refused 0 "[\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\",\"8\",\"9\",\"A\",\"B\",\"C\",\"D\",\"E\",\"F\",\"G\",\"H\"]"
'

test_expect_success 'a re-signed publication of 16 IDs in byte order carries over' '
	malformed 1 "[\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\",\"8\",\"9\",\"A\",\"B\",\"C\",\"D\",\"E\",\"F\",\"G\"]" &&
	append t7007b &&
	check 5 "
assert pub[\"operations\"][1][\"fixes\"] == list(\"123456789ABCDEFG\"), pub
assert pub[\"operations\"][0][\"fixes\"] == [\"A\", \"B\"], pub
assert \"fixes\" not in pub[\"operations\"][4], pub
"
'

test_done
