#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6127 -- the config image's settings, keys and registries were read
# through /proc/self/fd/<n>/... path strings, and /proc is root's to
# replace in a mount namespace of its own, or to mount over under
# /proc/<pid>/fd before the exec: a tree of root's with an entry for
# every descriptor number put root's shirudo.conf in effect, here with
# an eventlog limit that refuses every load. Every read must go through
# the verified root's descriptor, so a load under such a tree behaves
# as one without it.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v unshare >/dev/null 2>&1 || test_skip_all "no unshare"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-lifecycle
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME"
[ -s "$LOAD" ] && [ -s "$UNLOAD" ] || test_skip_all "missing lifecycle fixture"
[ ! -e "$PIN" ] || test_skip_all "$NAME is loaded"
W=/tmp/t6127
rm -rf "$W"
mkdir -p "$W"

cleanup() {
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -rf "$W"
}
trap cleanup EXIT

# The real /proc stays reachable under the tree for everything but the
# descriptor entries, which all lead to root's configuration.
cat >"$W/fake.sh" <<'SH'
set -e
W=$1
mount --make-rprivate /
mount -t tmpfs tmpfs "$W/proc"
mkdir -p "$W/proc/real" "$W/proc/self/fd" "$W/proc/conf/etc/shirudo"
mount --bind /proc "$W/proc/real"
printf 'eventlog.max_bytes = 1\n' >"$W/proc/conf/etc/shirudo/shirudo.conf"
n=3
while [ "$n" -le 64 ]; do
	ln -s "$W/proc/conf" "$W/proc/self/fd/$n"
	n=$((n + 1))
done
for e in exe mounts mountinfo status stat maps cmdline environ; do
	ln -s "$W/proc/real/self/$e" "$W/proc/self/$e"
done
for e in sys filesystems modules config.gz uptime meminfo; do
	ln -s "$W/proc/real/$e" "$W/proc/$e"
done
mount --bind "$W/proc" /proc
shift
exec "$@"
SH
mkdir -p "$W/proc"

test_expect_success 'a load under a substituted /proc takes the image configuration' '
	rc=0; unshare -m sh "$W/fake.sh" "$W" "$SHIRUDO_BIN" upatch load "$LOAD" \
		--no-precheck >/dev/null 2>"$W/err" || rc=$?;
	! grep -q "eventlog.max_bytes=1" "$W/err" &&
	[ "$rc" = 0 ] &&
	[ -e "$PIN/link" ]
'

test_expect_success 'and the same unload under it' '
	unshare -m sh "$W/fake.sh" "$W" "$SHIRUDO_BIN" upatch unload "$UNLOAD" \
		--no-precheck >/dev/null 2>&1 &&
	[ ! -e "$PIN" ]
'

test_done
