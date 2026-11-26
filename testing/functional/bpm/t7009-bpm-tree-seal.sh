#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7009 -- bpm tree append seals a segment that holds --segment-ops
# operations, or that one append would take past 512, tags the sealed
# manifest segment-<k> with its bytes unchanged, and starts the next
# segment at the sealed head with the sealed digest and the history root
# there, recomputed here. An append is never split; fixes and selectors
# carry across a seal. The XDP class check reaches the adds of the sealed
# segments, fetched by digest and verified as a joining node verifies
# them, an add a later segment deleted no longer counts, and an add
# without XDP classes fetches no sealed segment.
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

# A package named $1 of one upatch per further name, each an XDP program
# for the device classes $2 or, when $2 is empty, an fentry program, with
# the tree entry lines $3.
package() {
	name=$1 classes=$2 entry=$3
	shift 3
	if [ -n "$classes" ]; then
		program="SEC(\"xdp/$classes\")\nint xdp_pass(struct xdp_md *ctx)\n{\n\treturn XDP_PASS;\n}"
	else
		program="SEC(\"fentry/do_nanosleep\")\nint BPF_PROG(fn)\n{\n\treturn 0;\n}"
	fi
	mkdir -p "$WORK/$name" &&
	ln -s "$REPO/vendor" "$WORK/$name/vendor" &&
	ln -s "$REPO/bpf" "$WORK/$name/bpf" &&
	printf '[package]\nname = "%s"\n' "$name" >"$WORK/$name/Beefile" &&
	for id in "$@"; do
		printf '// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause\n#include "vmlinux.h"\n#include <bpf/bpf_helpers.h>\n#include <bpf/bpf_tracing.h>\n\nchar _license[] SEC("license") = "Dual BSD/GPL";\n\n%b\n' \
			"$program" >"$WORK/$name/$id.bpf.c" &&
		printf '\n[[upatches]]\nsource = "%s.bpf.c"\n\n[upatches.tree]\nid = "%s"\n%b' \
			"$id" "$id" "$entry" >>"$WORK/$name/Beefile" || return 1
	done &&
	( cd "$WORK" && "$S" bpm build "$name" --version 1.0.0 \
		--keys-dir "$WORK/keys" ) >&2
}

SITE_A='\n[upatches.tree.selector.labels]\nsite = ["a"]\n'
test_expect_success 'bpm build packages the upatches the appends publish' '
	package t7009a "" \
		"fixes = [\"EXAMPLE-0102\", \"EXAMPLE-0101\"]$SITE_A" t7009a &&
	package t7009m "" "" t7009m1 t7009m2 t7009m3 &&
	package t7009xa 2 "$SITE_A" t7009xa &&
	package t7009xb 2 "$SITE_A" t7009xb
'
for p in t7009a t7009m t7009xa t7009xb; do
	[ -s "$WORK/$p-1.0.0.bee" ] || test_done
done

PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
REG="$WORK/registry"
LOG="$WORK/requests.log"
python3 ./helper/test-oci-registry.py --root "$REG" --port "$PORT" --writable \
	--log "$LOG" --ready-file "$WORK/ready" &
SERVER_PID=$!
i=0
while [ ! -e "$WORK/ready" ]; do
	i=$((i + 1))
	[ "$i" -lt 100 ] || test_skip_all "registry fixture did not start"
	sleep .05
done

# Append package $1 to repository ns/$2 with the options that follow.
append() {
	pkg=$1 tree=$2
	shift 2
	"$S" bpm tree append "$WORK/$pkg-1.0.0.bee" \
		"oci://127.0.0.1:$PORT/ns/$tree" --tree-id "$tree" \
		--keys-dir "$WORK/keys" "$@" >"$WORK/out" 2>"$WORK/err"
}

# The checks of the segments of a tree, read from the registry files.
cat >"$WORK/segments.py" <<\PY
import hashlib, json, pathlib

DOC = "application/vnd.shirudo.upatch.tree.v1+json"
SIG = "application/vnd.shirudo.upatch.tree.signature.v1"


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def layer(manifest, media):
    return [l for l in json.loads(manifest)["layers"]
            if l["mediaType"] == media][0]["digest"]


def segment(repo, ref):
    manifest = (repo / "manifests" / ref).read_bytes()
    document = (repo / "blobs" / layer(manifest, DOC)).read_bytes()
    return {"digest": sha(manifest), "manifest": manifest,
            "document": document, "doc": json.loads(document)}


def op_digest(op):
    canonical = {k: v for k, v in op.items()
                 if k not in ("operation_digest", "fixes")}
    return sha(json.dumps(canonical, separators=(",", ":")).encode())


def history(ops):
    root = bytes(32)
    for op in ops:
        step = b"shirudo-tree-history\0" + root
        root = hashlib.sha256(step + bytes.fromhex(op["operation_digest"][7:])).digest()
    return root.hex()


def walk(repo, ref="stable"):
    """Every segment, oldest first, each checked against its successor."""
    chain = [segment(repo, ref)]
    while chain[0]["doc"]["base"]["seq"]:
        succ = chain[0]["doc"]
        pred = segment(repo, succ["base"]["segment_manifest_digest"])
        assert pred["digest"] == succ["base"]["segment_manifest_digest"], pred
        assert pred["doc"]["head"]["seq"] == succ["base"]["seq"], succ
        assert pred["doc"]["generation"] < succ["generation"], succ
        assert pred["doc"]["tree_id"] == succ["tree_id"], succ
        chain.insert(0, pred)
    ops = []
    for k, seg in enumerate(chain):
        doc = seg["doc"]
        base = doc["base"]
        assert base["seq"] == len(ops), (k, base)
        if base["seq"]:
            assert set(base) == {"seq", "segment_manifest_digest",
                                 "history_root"}, base
            assert base["history_root"] == history(ops), (k, base)
        else:
            assert base == {"seq": 0}, base
        for i, op in enumerate(doc["operations"]):
            assert op["seq"] == base["seq"] + 1 + i, op
            assert op["operation_digest"] == op_digest(op), op
        assert doc["head"]["seq"] == base["seq"] + len(doc["operations"]), doc
        ops += doc["operations"]
        if k + 1 < len(chain):
            tag = repo / "manifests" / f"segment-{k + 1}"
            assert tag.read_bytes() == seg["manifest"], k
    assert not (repo / "manifests" / f"segment-{len(chain)}").exists()
    return chain
PY

# Run the Python on standard input with the checks above and $@ as its
# arguments.
segments() {
	python3 - "$WORK" "$REG/ns" "$@"
}

test_expect_success 'appends fill a segment of --segment-ops operations' '
	append t7009a seal --segment-ops 2 &&
	append t7009a seal --segment-ops=2 &&
	cp "$REG/ns/seal/manifests/stable" "$WORK/sealed.manifest" &&
	segments <<-\PY
	import sys; sys.path.insert(0, sys.argv[1])
	import pathlib, segments as s
	chain = s.walk(pathlib.Path(sys.argv[2]) / "seal")
	assert len(chain) == 1, chain
	doc = chain[0]["doc"]
	assert doc["generation"] == 2 and doc["head"] == {"seq": 2}, doc
	PY
'

test_expect_success 'appending to a full segment seals and tags it' '
	append t7009a seal --segment-ops 2 &&
	grep -q "^oci://127.0.0.1:$PORT/ns/seal:stable sha256:" "$WORK/out" &&
	test ! -s "$WORK/err" &&
	cmp -s "$WORK/sealed.manifest" "$REG/ns/seal/manifests/segment-1" &&
	segments "$WORK/sealed.manifest" <<-\PY
	import sys; sys.path.insert(0, sys.argv[1])
	import pathlib, segments as s
	repo = pathlib.Path(sys.argv[2]) / "seal"
	sealed = pathlib.Path(sys.argv[3]).read_bytes()
	chain = s.walk(repo)
	assert len(chain) == 2, chain
	old, new = chain[0], chain[1]["doc"]
	assert old["manifest"] == sealed, "the sealed manifest moved"
	assert (repo / "manifests" / old["digest"]).read_bytes() == sealed
	assert new["generation"] == 3 and new["parent_manifest_digest"] == old["digest"], new
	assert new["base"] == {"seq": 2, "segment_manifest_digest": old["digest"],
	                       "history_root": s.history(old["doc"]["operations"])}, new
	assert [op["seq"] for op in new["operations"]] == [3], new
	PY
'

test_expect_success 'an append of several operations is not split' '
	append t7009m seal --segment-ops 2 &&
	test ! -e "$REG/ns/seal/manifests/segment-2" &&
	segments <<-\PY
	import sys; sys.path.insert(0, sys.argv[1])
	import pathlib, segments as s
	chain = s.walk(pathlib.Path(sys.argv[2]) / "seal")
	assert len(chain) == 2, chain
	ops = chain[1]["doc"]["operations"]
	assert [(op["seq"], op["id"]) for op in ops] == [
	    (3, "t7009a"), (4, "t7009m1"), (5, "t7009m2"), (6, "t7009m3")], ops
	PY
'

test_expect_success '--segment-ops changed between appends is honoured' '
	append t7009a seal --segment-ops 8 &&
	test ! -e "$REG/ns/seal/manifests/segment-2" &&
	cp "$REG/ns/seal/manifests/stable" "$WORK/sealed2.manifest" &&
	append t7009a seal --segment-ops=5 &&
	cmp -s "$WORK/sealed2.manifest" "$REG/ns/seal/manifests/segment-2" &&
	append t7009a seal &&
	test ! -e "$REG/ns/seal/manifests/segment-3" &&
	segments <<-\PY
	import sys; sys.path.insert(0, sys.argv[1])
	import pathlib, segments as s
	chain = s.walk(pathlib.Path(sys.argv[2]) / "seal")
	assert [(c["doc"]["base"]["seq"], c["doc"]["head"]["seq"]) for c in chain] == [
	    (0, 2), (2, 7), (7, 9)], chain
	assert chain[2]["doc"]["generation"] == 7, chain[2]["doc"]
	PY
'

test_expect_success 'fixes and selectors survive across a seal' '
	segments <<-\PY
	import sys; sys.path.insert(0, sys.argv[1])
	import pathlib, segments as s
	chain = s.walk(pathlib.Path(sys.argv[2]) / "seal")
	adds = [op for c in chain for op in c["doc"]["operations"]
	        if op["id"] == "t7009a"]
	assert [op["seq"] for op in adds] == [1, 2, 3, 7, 8, 9], adds
	for op in adds:
	    assert op["fixes"] == ["EXAMPLE-0101", "EXAMPLE-0102"], op
	    assert op["selector"] == {"labels": {"site": ["a"]}}, op
	    assert op["artifact"] == adds[0]["artifact"], op
	PY
'

test_expect_success 'a seal an earlier run tagged keeps its tag' '
	append t7009a retag --segment-ops 1 &&
	cp "$REG/ns/retag/manifests/stable" "$REG/ns/retag/manifests/segment-1" &&
	append t7009a retag --segment-ops 1 &&
	test ! -e "$REG/ns/retag/manifests/segment-2" &&
	append t7009a retag --segment-ops 1 &&
	test -e "$REG/ns/retag/manifests/segment-2" &&
	test ! -e "$REG/ns/retag/manifests/segment-3" &&
	segments <<-\PY
	import sys; sys.path.insert(0, sys.argv[1])
	import pathlib, segments as s
	chain = s.walk(pathlib.Path(sys.argv[2]) / "retag")
	assert len(chain) == 3, chain
	PY
'

test_expect_success '--segment-ops outside 1 to 512 is refused' '
	cp "$REG/ns/seal/manifests/stable" "$WORK/before.manifest" &&
	for n in 0 513 -1 1x; do
		! append t7009a seal --segment-ops "$n" &&
		grep -qx "bpm tree append: --segment-ops takes a number from 1 to 512" \
			"$WORK/err" || exit 1
	done &&
	! append t7009a seal --segment-ops "" &&
	grep -qx "bpm tree append: --segment-ops takes a value, not an empty one" \
		"$WORK/err" &&
	cmp -s "$WORK/before.manifest" "$REG/ns/seal/manifests/stable"
'

# Publish at ns/$1:stable the first segment of $2 operations, copies of
# the first operation of ns/seal at the next sequence numbers, signed
# with the operator key; with $3, the last one's digest is wrong.
synthetic() {
	python3 - "$WORK" "$REG/ns" "$@" <<-\PY &&
	import sys; sys.path.insert(0, sys.argv[1])
	import json, pathlib, segments as s
	work, ns = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
	n, bad = int(sys.argv[4]), len(sys.argv) > 5
	op = s.walk(ns / "seal")[0]["doc"]["operations"][0]
	ops = []
	for seq in range(1, n + 1):
	    o = {k: v for k, v in op.items() if k not in ("fixes", "operation_digest")}
	    o["seq"] = seq
	    o["operation_digest"] = s.op_digest(o)
	    ops.append(o)
	if bad:
	    ops[-1]["operation_digest"] = ops[0]["operation_digest"]
	doc = {"schema": 1, "tree_id": sys.argv[3], "generation": 1,
	       "base": {"seq": 0}, "operations": ops, "head": {"seq": n}}
	(work / "synthetic.json").write_bytes(
	    json.dumps(doc, separators=(",", ":")).encode())
	PY
	openssl cms -sign -binary -md sha512 -in "$WORK/synthetic.json" \
		-signer "$WORK/keys/cert.der" -inkey "$WORK/keys/signing_key.pem" \
		-outform DER -out "$WORK/synthetic.sig" -nosmimecap -nocerts -keyid &&
	python3 - "$WORK" "$REG/ns" "$1" <<-\PY
	import sys; sys.path.insert(0, sys.argv[1])
	import json, pathlib, segments as s
	work, ns = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
	repo = ns / sys.argv[3]
	(repo / "manifests").mkdir(parents=True)
	(repo / "blobs").mkdir()
	manifest = json.loads((ns / "seal" / "manifests" / "segment-1").read_bytes())
	for l in manifest["layers"]:
	    body = (work / ("synthetic.json" if l["mediaType"] == s.DOC
	                    else "synthetic.sig")).read_bytes()
	    l["digest"], l["size"] = s.sha(body), len(body)
	    (repo / "blobs" / l["digest"]).write_bytes(body)
	config = manifest["config"]["digest"]
	(repo / "blobs" / config).write_bytes((ns / "seal" / "blobs" / config).read_bytes())
	raw = json.dumps(manifest, separators=(",", ":")).encode()
	(repo / "manifests" / "stable").write_bytes(raw)
	(repo / "manifests" / s.sha(raw)).write_bytes(raw)
	PY
}

test_expect_success 'an append that fills a segment to 512 does not seal' '
	synthetic full 509 &&
	append t7009m full --segment-ops 512 &&
	append t7009a full --segment-ops 512 &&
	segments <<-\PY
	import sys; sys.path.insert(0, sys.argv[1])
	import pathlib, segments as s
	chain = s.walk(pathlib.Path(sys.argv[2]) / "full")
	assert [(c["doc"]["base"]["seq"], c["doc"]["head"]["seq"]) for c in chain] == [
	    (0, 512), (512, 513)], chain
	PY
'

test_expect_success 'an append that would pass 512 operations seals first' '
	synthetic over 510 &&
	cp "$REG/ns/over/manifests/stable" "$WORK/over.manifest" &&
	append t7009m over --segment-ops 512 &&
	cmp -s "$WORK/over.manifest" "$REG/ns/over/manifests/segment-1" &&
	segments <<-\PY
	import sys; sys.path.insert(0, sys.argv[1])
	import pathlib, segments as s
	chain = s.walk(pathlib.Path(sys.argv[2]) / "over")
	assert [(c["doc"]["base"]["seq"], c["doc"]["head"]["seq"]) for c in chain] == [
	    (0, 510), (510, 513)], chain
	PY
'

test_expect_success 'an append to a segment that does not verify is refused' '
	synthetic bad 3 wrong &&
	cp "$REG/ns/bad/manifests/stable" "$WORK/bad.manifest" &&
	! append t7009a bad &&
	grep -qx "bpm tree append: the publication at oci://127.0.0.1:$PORT/ns/bad:stable does not verify" \
		"$WORK/err" &&
	cmp -s "$WORK/bad.manifest" "$REG/ns/bad/manifests/stable"
'

# Every request of the last append for a segment before the one it had
# in hand, the stable manifest $2 of ns/$1 before it: a manifest by
# digest, or its document or signature.
sealed_requests() {
	python3 - "$WORK" "$REG/ns" "$1" "$2" "$LOG" <<-\PY
	import sys; sys.path.insert(0, sys.argv[1])
	import json, pathlib, segments as s
	repo = pathlib.Path(sys.argv[2]) / sys.argv[3]
	hand = pathlib.Path(sys.argv[4]).read_bytes()
	base = json.loads((repo / "blobs" / s.layer(hand, s.DOC)).read_bytes())["base"]
	paths = set()
	for seg in s.walk(repo):
	    if seg["doc"]["head"]["seq"] > base["seq"]:
	        break
	    paths.add("manifests/" + seg["digest"])
	    for l in json.loads(seg["manifest"])["layers"]:
	        paths.add("blobs/" + l["digest"])
	for line in pathlib.Path(sys.argv[5]).read_text().splitlines():
	    method, path, _ = line.split("\t")
	    if any(path.endswith("/" + p) for p in paths):
	        print(method, path)
	PY
}

test_expect_success 'an XDP add whose class a live add of a sealed segment selects is refused' '
	append t7009xa xdp --segment-ops 1 &&
	append t7009a xdp --segment-ops 1 &&
	cp "$REG/ns/xdp/manifests/stable" "$WORK/xdp.manifest" &&
	! append t7009xb xdp --segment-ops 1 &&
	grep -q "t7009xb and t7009xa (seq 1) both select XDP device classes 2 " \
		"$WORK/err" &&
	cmp -s "$WORK/xdp.manifest" "$REG/ns/xdp/manifests/stable" &&
	test ! -e "$REG/ns/xdp/manifests/segment-2" &&
	! ls "$REG/ns/xdp/manifests" | grep -q "upatch-t7009xb"
'

test_expect_success 'an XDP add is taken once a later segment deleted the earlier add' '
	append t7009xa xdp --segment-ops 1 --op delete &&
	append t7009xb xdp --segment-ops 1 &&
	segments <<-\PY
	import sys; sys.path.insert(0, sys.argv[1])
	import pathlib, segments as s
	chain = s.walk(pathlib.Path(sys.argv[2]) / "xdp")
	ops = [(op["seq"], op["op"], op["id"]) for c in chain for op in c["doc"]["operations"]]
	assert ops == [(1, "add", "t7009xa"), (2, "add", "t7009a"),
	               (3, "delete", "t7009xa"), (4, "add", "t7009xb")], ops
	assert len(chain) == 4, chain
	PY
'

test_expect_success 'an add without XDP classes fetches no sealed segment' '
	cp "$REG/ns/xdp/manifests/stable" "$WORK/hand.manifest" &&
	: >"$LOG" &&
	append t7009a xdp --segment-ops 1 &&
	test -e "$REG/ns/xdp/manifests/segment-4" &&
	sealed_requests xdp "$WORK/hand.manifest" >"$WORK/fetched" &&
	test ! -s "$WORK/fetched" &&
	cp "$REG/ns/xdp/manifests/stable" "$WORK/hand.manifest" &&
	: >"$LOG" &&
	append t7009a xdp --segment-ops 64 &&
	test ! -e "$REG/ns/xdp/manifests/segment-5" &&
	sealed_requests xdp "$WORK/hand.manifest" >"$WORK/fetched" &&
	test ! -s "$WORK/fetched" &&
	! grep -q "manifests/segment-" "$LOG"
'

test_expect_success 'an XDP add fetches every sealed segment by digest' '
	cp "$REG/ns/xdp/manifests/stable" "$WORK/hand.manifest" &&
	: >"$LOG" &&
	append t7009xb xdp &&
	sealed_requests xdp "$WORK/hand.manifest" >"$WORK/fetched" &&
	test "$(grep -c "^GET .*/manifests/sha256:" "$WORK/fetched")" -eq 4
'

test_expect_success 'an XDP add refuses a sealed segment that is not the one named' '
	first=$(segments <<-\PY
	import sys; sys.path.insert(0, sys.argv[1])
	import pathlib, segments as s
	print(s.walk(pathlib.Path(sys.argv[2]) / "xdp")[0]["digest"])
	PY
	) &&
	cp "$REG/ns/xdp/manifests/$first" "$WORK/first.manifest" &&
	cp "$REG/ns/xdp/manifests/segment-2" "$REG/ns/xdp/manifests/$first" &&
	cp "$REG/ns/xdp/manifests/stable" "$WORK/xdp.manifest" &&
	! append t7009xb xdp &&
	grep -qx "bpm tree append: the sealed segment $first, which ends at seq 1, does not verify" \
		"$WORK/err" &&
	cmp -s "$WORK/xdp.manifest" "$REG/ns/xdp/manifests/stable" &&
	cp "$WORK/first.manifest" "$REG/ns/xdp/manifests/$first"
'

test_done
