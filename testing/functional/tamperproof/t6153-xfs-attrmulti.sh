#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6153 -- XFS_IOC_ATTRMULTI_BY_HANDLE changes attributes past every xattr
# hook, so a task without authority may not issue it on an XFS file
# system: it fails with EACCES and counts as XattrHandle. On any other
# file system the same number reaches the file system, which does not
# know it. The XFS case needs XFS in the kernel and mkfs.xfs, which the
# slim test VM kernel lacks.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
H=helper/test-xfs-attrmulti
[ -x "$H" ] || test_skip_all "test-xfs-attrmulti helper not built"
W=$(mktemp -d)
cleanup() {
	! mountpoint -q "$W/mnt" || umount "$W/mnt"
	rm -rf "$W"
}
trap cleanup EXIT
counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
print(json.load(sys.stdin)["tamper_attempts"]["counters"][sys.argv[1]])
' "$1"
}
before=$(counter XattrHandle) || test_skip_all "no tamper counters"
: >"$W/file"

test_expect_success 'the ioctl number on another file system is not refused' '
	[ "$("$H" "$W/file")" != 13 ] &&
	[ "$(counter XattrHandle)" = "$before" ]
'
if command -v mkfs.xfs >/dev/null 2>&1 && grep -qw xfs /proc/filesystems &&
	truncate -s 320M "$W/xfs.img" && mkfs.xfs -q "$W/xfs.img" &&
	mkdir "$W/mnt" && mount -o loop "$W/xfs.img" "$W/mnt" &&
	: >"$W/mnt/file"; then
	test_expect_success 'attrmulti by handle is refused on XFS and counted' '
		[ "$("$H" "$W/mnt/file")" = 13 ] &&
		[ "$(counter XattrHandle)" -gt "$before" ]
	'
else
	echo "# no XFS here; the XFS case is not run"
fi
test_done
