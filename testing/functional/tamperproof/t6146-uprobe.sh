#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6146 -- a uprobe on the runtime binary takes the authority of the
# shirudo tasks whose memory it reaches: while a probe set through tracefs
# sits at the binary's entry point, a load is refused and SealUprobe
# counts it, and shirudo works again once the probe is gone.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
T=/sys/kernel/tracing
[ -w "$T/uprobe_events" ] || test_skip_all "no uprobe events in tracefs"
FIXTURES=$SHIRUDO_TEST_FIXTURES_DIR
NAME=shirudo-test-basic
PINDIR="/run/shirudo/bpffs/upatches/$NAME"
[ -s "$FIXTURES/$NAME.upatch" ] || test_skip_all "missing fixture $NAME"
RUNTIME=$(runtime_binary)
GROUP=shirudo_t6146
cleanup() {
	[ ! -e "$T/events/$GROUP/entry/enable" ] ||
		echo 0 >"$T/events/$GROUP/entry/enable" || :
	echo "-:$GROUP/entry" >>"$T/uprobe_events" 2>/dev/null || :
	[ ! -e "$PINDIR" ] ||
		"$SHIRUDO_BIN" upatch unload "$FIXTURES/$NAME.unload.upatch" \
			>/dev/null 2>&1 || :
}
trap cleanup EXIT
counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
print(json.load(sys.stdin)["tamper_attempts"]["counters"][sys.argv[1]])
' "$1"
}
# The file offset of the ELF entry point, from the segment that holds it.
entry_offset() {
	python3 - "$1" <<'PY'
import struct, sys
elf = open(sys.argv[1], "rb").read()
entry, = struct.unpack_from("<Q", elf, 24)
phoff, = struct.unpack_from("<Q", elf, 32)
phentsize, phnum = struct.unpack_from("<HH", elf, 54)
for i in range(phnum):
    kind, flags, offset, vaddr, _, filesz = struct.unpack_from(
        "<IIQQQQ", elf, phoff + i * phentsize)
    if kind == 1 and flags & 1 and vaddr <= entry < vaddr + filesz:
        print(hex(entry - vaddr + offset))
        break
else:
    sys.exit(1)
PY
}
ENTRY=$(entry_offset "$RUNTIME") || test_skip_all "no entry point in $RUNTIME"
before=$(counter SealUprobe) || test_skip_all "no tamper counters"
[ ! -e "$PINDIR" ] ||
	"$SHIRUDO_BIN" upatch unload "$FIXTURES/$NAME.unload.upatch" \
		>/dev/null 2>&1
[ ! -e "$PINDIR" ] || test_skip_all "$NAME cannot be unloaded"

test_expect_success 'root sets a uprobe at the entry of the runtime binary' '
	echo "p:$GROUP/entry $RUNTIME:$ENTRY" >>"$T/uprobe_events" &&
	echo 1 >"$T/events/$GROUP/entry/enable"
'
test_expect_success 'a load from a task the probe reached is refused' '
	! "$SHIRUDO_BIN" upatch load "$FIXTURES/$NAME.upatch" >/dev/null 2>&1 &&
	[ ! -e "$PINDIR" ]
'
test_expect_success 'the probe is gone again' '
	echo 0 >"$T/events/$GROUP/entry/enable" &&
	echo "-:$GROUP/entry" >>"$T/uprobe_events" &&
	[ ! -e "$T/events/$GROUP/entry" ]
'
test_expect_success 'the lost authority is counted as SealUprobe' '
	[ "$(counter SealUprobe)" -gt "$before" ]
'
test_expect_success 'a load without the probe succeeds and is undone' '
	"$SHIRUDO_BIN" upatch load "$FIXTURES/$NAME.upatch" >/dev/null 2>&1 &&
	[ -e "$PINDIR/link" ] &&
	"$SHIRUDO_BIN" upatch unload "$FIXTURES/$NAME.unload.upatch" \
		>/dev/null 2>&1 &&
	[ ! -e "$PINDIR" ]
'
test_done
