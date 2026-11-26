#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6120 -- the pins hold the enforcement links through the bpffs
# superblock, which goes with its last mount. A lazy unmount of /run
# took the private bpffs and every link with it, and so did one of a
# copy of /run in a namespace whose mounts still propagated to init's.
# The sb_umount guard walks what an unmount would take, by subtree and
# by propagation, and refuses one that reaches the bpffs mount init
# made, counted as BpffsUmountAbove. A private copy in a namespace of
# its own is any process's to drop and enforcement stays.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v unshare >/dev/null 2>&1 || test_skip_all "no unshare"
C=helper/test-bpf-cmd
[ -x "$C" ] || test_skip_all "test-bpf-cmd helper not built"
B=/run/shirudo/bpffs
W=/tmp/t6120
mkdir -p "$W/run"
# Under the library's errexit a failing step would end the cleanup. A
# tree with a bind of /run still beneath it is left alone: removing it
# would empty the real /run through the bind.
cleanup() {
	mount --make-rprivate "$W" 2>/dev/null || true
	umount -l "$W" 2>/dev/null || true
	mountpoint -q "$W/run" || rm -rf "$W" 2>/dev/null || true
}
trap cleanup EXIT

counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
print(json.load(sys.stdin)["tamper_attempts"]["counters"][sys.argv[1]])
' "$1"
}

enforcing() {
	mountpoint -q "$B" && [ "$(./$C LINK_CREATE)" = "errno=13" ]
}

test_expect_success 'enforcement is live to begin with' '
	enforcing
'

# A bind of a shared mount is a peer of its source: the root's binds are
# peers of the root, under which the bpffs sits, and unmounting one must
# not count as unmounting the root.
test_expect_success 'a bind mount of a root file system path is any process'"'"'s to unmount' '
	mkdir -p "$W/bind" &&
	mount --bind /var/lib "$W/bind" &&
	umount "$W/bind" &&
	! mountpoint -q "$W/bind" &&
	enforcing
'

test_expect_success 'a lazy unmount of /run is refused and counted' '
	before=$(counter BpffsUmountAbove) &&
	! umount -l /run 2>/dev/null &&
	enforcing &&
	[ "$(counter BpffsUmountAbove)" -gt "$before" ]
'

test_expect_success 'a lazy unmount of a copy of /run that propagates is refused' '
	! unshare -m --propagation unchanged umount -l /run 2>/dev/null &&
	enforcing
'

test_expect_success 'a lazy unmount of a private copy of /run is harmless' '
	unshare -m umount -l /run &&
	enforcing
'

# A bind of a directory on itself, so that it can be unmounted, made
# private first so that nothing mounted beneath it propagates to a copy
# under the root mount, with a recursive bind of /run beneath it: peers
# of the real mounts.
test_expect_success 'a lazy unmount of a tree of peers of /run is refused' '
	mount --bind "$W" "$W" &&
	mount --make-private "$W" &&
	mount --rbind /run "$W/run" &&
	mountpoint -q "$W/run/shirudo/bpffs" &&
	! umount -l "$W" 2>/dev/null &&
	mountpoint -q "$W/run/shirudo/bpffs" &&
	enforcing
'

test_expect_success 'the same tree made private is any process'"'"'s to drop' '
	mount --make-rprivate "$W" &&
	umount -l "$W" &&
	! mountpoint -q "$W/run/shirudo/bpffs" &&
	enforcing
'

test_done
