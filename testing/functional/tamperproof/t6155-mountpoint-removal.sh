#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6155 -- removing a dentry detaches what is mounted on it in every mount
# namespace, without an unmount hook: from a namespace where /run is not
# mounted, root cannot remove or rename the directory init's /run covers,
# which would take the private bpffs, and with it the enforcement links,
# along. Both are refused and counted as BpffsUmountAbove.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v unshare >/dev/null 2>&1 || test_skip_all "no unshare"
mountpoint -q /run/shirudo/bpffs || test_skip_all "no private bpffs"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
print(json.load(sys.stdin)["tamper_attempts"]["counters"][sys.argv[1]])
' "$1"
}
# In a namespace of its own, drops /run there and runs python $1 on the
# directory below it; prints the errno name, or done.
beneath() {
	unshare -m sh -c '
		mount --make-rprivate / || exit 3
		while mountpoint -q /run; do umount -l /run || exit 3; done
		python3 -c "
import errno, os, sys
try:
    $1
    print(\"done\")
except OSError as e:
    print(errno.errorcode[e.errno])
"' sh "$1"
}
before=$(counter BpffsUmountAbove) || test_skip_all "no tamper counters"

test_expect_success 'rmdir of the directory under /run is refused and counted' '
	beneath "os.rmdir(\"/run\")" >"$W/out" &&
	{ grep -qx EPERM "$W/out" || { cat "$W/out" >&2; false; }; } &&
	[ "$(counter BpffsUmountAbove)" -gt "$before" ]
'
test_expect_success 'and so is a rename of it' '
	beneath "os.rename(\"/run\", \"/run.t6155\")" >"$W/out" &&
	{ grep -qx EPERM "$W/out" || { cat "$W/out" >&2; false; }; }
'
test_expect_success 'the private bpffs is still mounted and status reads it' '
	mountpoint -q /run/shirudo/bpffs &&
	"$SHIRUDO_BIN" status >/dev/null
'
test_done
