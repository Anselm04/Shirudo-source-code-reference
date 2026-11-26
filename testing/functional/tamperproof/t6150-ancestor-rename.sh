#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6150 -- the directories above the state root carry the ancestor mark,
# and root can neither rename one, which would move the sealed tree aside
# for the next boot to label another in its place, nor remove the mark,
# while the directories beside the state root stay root's to rename.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
MARK=security.bpf.shirudo.ancestor
W=$(mktemp -d)
cleanup() {
	[ ! -e /var/lib.t6150 ] || mv /var/lib.t6150 /var/lib || :
	rm -rf /var/lib/t6150-a /var/lib/t6150-b "$W"
}
trap cleanup EXIT
counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
print(json.load(sys.stdin)["tamper_attempts"]["counters"][sys.argv[1]])
' "$1"
}
# Run python $1 with the rest as arguments; prints the errno name it hit.
attempt() {
	python3 -c "
import errno, os, sys
try:
    $1
    print('done')
except OSError as e:
    print(errno.errorcode[e.errno])
" "$@" 2>&1
}
[ "$(stat -c %d /var/lib/shirudo)" = "$(stat -c %d /var/lib)" ] ||
	test_skip_all "the state root is a file system of its own"
rename_before=$(counter SealRename) || test_skip_all "no tamper counters"
label_before=$(counter SealLabel)

test_expect_success 'the directories above the state root carry the mark' '
	attempt "os.getxattr(\"/var/lib\", \"$MARK\")" >"$W/out" &&
	grep -qx done "$W/out" &&
	if [ "$(stat -c %d /var)" = "$(stat -c %d /var/lib)" ]; then
		attempt "os.getxattr(\"/var\", \"$MARK\")" >"$W/out" &&
		grep -qx done "$W/out"
	fi
'
test_expect_success 'a rename of one is refused and counted' '
	attempt "os.rename(\"/var/lib\", \"/var/lib.t6150\")" >"$W/out" &&
	grep -qx EACCES "$W/out" &&
	[ -d /var/lib/shirudo ] && [ ! -e /var/lib.t6150 ] &&
	[ "$(counter SealRename)" -gt "$rename_before" ]
'
test_expect_success 'and so is the removal of the mark' '
	attempt "os.removexattr(\"/var/lib\", \"$MARK\")" >"$W/out" &&
	grep -qx EACCES "$W/out" &&
	[ "$(counter SealLabel)" -gt "$label_before" ]
'
test_expect_success 'a directory beside the state root still renames' '
	mkdir /var/lib/t6150-a &&
	mv /var/lib/t6150-a /var/lib/t6150-b &&
	[ -d /var/lib/t6150-b ]
'
test_done
