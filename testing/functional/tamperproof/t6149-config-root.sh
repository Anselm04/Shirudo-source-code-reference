#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6149 -- shirudo reads the config image only from the root of its
# mount: a directory of the image bound in its place, in a namespace with
# a /run of root's making, has the image's device but every relative path
# leads elsewhere in the image, and a command there refuses the config.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v unshare >/dev/null 2>&1 || test_skip_all "no unshare"
mountpoint -q /run/shirudo/config || test_skip_all "no config image mounted"
SUB=$(find /run/shirudo/config -mindepth 1 -maxdepth 1 -type d \
	! -name lost+found | head -1)
[ -n "$SUB" ] || test_skip_all "the config image has no directory"
RUNTIME=$(runtime_binary)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
mkdir -p "$W/run"
cat >"$W/run.sh" <<EOF
set -e
mount -t tmpfs none "$W/run"
mkdir -p "$W/run/shirudo/bpffs" "$W/run/shirudo/runtime" "$W/run/shirudo/config"
mount --bind /run/shirudo/bpffs "$W/run/shirudo/bpffs"
mount --bind /run/shirudo/runtime "$W/run/shirudo/runtime"
mount --bind "\$1" "$W/run/shirudo/config"
mount --rbind "$W/run" /run
"$RUNTIME" upatch list >"$W/out" 2>&1
EOF

test_expect_success 'a command reads the config from the root of its mount' '
	unshare -m sh "$W/run.sh" /run/shirudo/config
'
test_expect_success 'and refuses a directory of the image bound in its place' '
	! unshare -m sh "$W/run.sh" "$SUB" &&
	grep -q "image state: Structure needs cleaning" "$W/out"
'
test_done
