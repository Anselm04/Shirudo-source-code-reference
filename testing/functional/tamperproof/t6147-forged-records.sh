#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6147 -- the undo pass takes only the records the register vouches for:
# a /run of root's making with a pending record that unloads a loaded
# upatch, or another boot's ID bound over /proc in a namespace of root's,
# makes a load there detach nothing, and the measured upatch stays loaded.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v unshare >/dev/null 2>&1 || test_skip_all "no unshare"
FIXTURES=$SHIRUDO_TEST_FIXTURES_DIR
NAME=shirudo-test-basic
PINDIR="/run/shirudo/bpffs/upatches/$NAME"
ARCHIVE="/var/lib/shirudo/upatches/$NAME.upatch"
EVENTLOG=/var/lib/shirudo/eventlog
RUNTIME=$(runtime_binary)
W=$(mktemp -d)
cleanup() {
	[ ! -e "$PINDIR" ] ||
		"$SHIRUDO_BIN" upatch unload "$FIXTURES/$NAME.unload.upatch" \
			>/dev/null 2>&1 || :
	rm -rf "$W"
}
trap cleanup EXIT
for f in "$FIXTURES/$NAME.upatch" "$FIXTURES/$NAME.unload.upatch" \
	 "$FIXTURES/shirudo-test-marker.upatch"; do
	[ -s "$f" ] || test_skip_all "missing fixture $f"
done
require_loaded "$NAME" || test_skip_all "$NAME does not load"
BOOT=$(cat /proc/sys/kernel/random/boot_id)
PAYLOAD=$(grep "\"name\":\"$NAME\"" "$EVENTLOG" | tail -1 |
	  sed 's/.*"payload_sha256":"\([0-9a-f]*\)".*/\1/')
[ ${#PAYLOAD} = 64 ] || test_skip_all "no record of the load"
# An artifact the load refuses once it has run its undo pass.
cp "$FIXTURES/shirudo-test-marker.upatch" "$W/bad.upatch"
printf '\001' | dd of="$W/bad.upatch" bs=1 conv=notrunc \
	seek=$(($(stat -c %s "$W/bad.upatch") - 1)) 2>/dev/null
lines=$(wc -l <"$EVENTLOG")

# The forged record unloads the upatch in this boot, by its own boot ID.
printf '{"schema":1,"digest":"%064d","type":"upatch_unload","boot_id":"%s","upatch":{"name":"%s","payload_sha256":"%s"}}\n' \
	0 "$BOOT" "$NAME" "$PAYLOAD" >"$W/pending"
cat >"$W/run.sh" <<EOF
set -e
mount -t tmpfs none "$W/run"
mkdir -p "$W/run/shirudo/bpffs" "$W/run/shirudo/runtime" "$W/run/shirudo/config"
mount --bind /run/shirudo/bpffs "$W/run/shirudo/bpffs"
mount --bind /run/shirudo/runtime "$W/run/shirudo/runtime"
mount --bind /run/shirudo/config "$W/run/shirudo/config"
cp "$W/pending" "$W/run/shirudo/eventlog.pending"
mount --rbind "$W/run" /run
"$RUNTIME" upatch load --no-precheck "$W/bad.upatch" >"$W/out" 2>&1 || :
EOF
mkdir -p "$W/run"

test_expect_success 'a load under a /run of root'"'"'s making detaches nothing' '
	unshare -m sh "$W/run.sh" &&
	! grep -q "was pinned without a record" "$W/out" &&
	[ -e "$PINDIR/link" ] &&
	[ -s "$ARCHIVE" ]
'
test_expect_success 'and its record never reaches the eventlog' '
	[ "$(wc -l <"$EVENTLOG")" = "$lines" ] &&
	! grep -q "\"digest\":\"0000000000000000" "$EVENTLOG"
'
test_expect_success 'another boot ID bound over /proc changes nothing either' '
	echo 00000000-0000-0000-0000-000000000000 >"$W/boot_id" &&
	unshare -m sh -c "mount --bind \"$W/boot_id\" /proc/sys/kernel/random/boot_id &&
		\"$RUNTIME\" upatch load --no-precheck \"$W/bad.upatch\"" \
		>"$W/out" 2>&1 || :
	! grep -q "was pinned without a record" "$W/out" &&
	[ -e "$PINDIR/link" ] &&
	[ -s "$ARCHIVE" ]
'
test_expect_success 'status still finds every pin in this boot'"'"'s records' '
	"$SHIRUDO_BIN" status 2>/dev/null | grep -q "UpatchesMeasured *OK"
'
test_done
