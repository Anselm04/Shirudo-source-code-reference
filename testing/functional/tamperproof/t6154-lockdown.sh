#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6154 -- bpf2 refuses what lockdown in integrity mode refuses, whatever
# the command line says, and /proc/kcore with it: an unsigned module and
# the reads and writes of the running kernel fail with EPERM and each
# counts on the integrity counter of its reason, which status, its JSON
# and the keepalive report, while the hibernation check every read of
# /sys/power/state makes counts nothing.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
d = json.load(sys.stdin)["integrity_attempts"]
print(d["total"] if sys.argv[1] == "total" else d["counters"][sys.argv[1]])
' "$1"
}
# Prints the errno name an open of $1 for reading fails with, or done.
open_errno() {
	python3 -c '
import errno, os, sys
try:
    os.close(os.open(sys.argv[1], os.O_RDONLY))
    print("done")
except OSError as e:
    print(errno.errorcode[e.errno])
' "$1"
}
counter total >/dev/null || test_skip_all "no integrity counters"

# The guest's modules are signed; a copy without the signature is what the
# kernel asks lockdown about.
test_expect_success 'a module without its signature is refused and counted' '
	module=$(find "/lib/modules/$(uname -r)" -name "*.ko" | head -1) &&
	[ -n "$module" ] &&
	now=$(counter ModuleSignature) &&
	python3 - "$module" "$W/unsigned.ko" >"$W/module" <<-\PY &&
	import ctypes, errno, os, platform, sys
	MARKER = b"~Module signature appended~\n"
	FINIT_MODULE = {"x86_64": 313, "aarch64": 273, "riscv64": 273}
	data = open(sys.argv[1], "rb").read()
	if not data.endswith(MARKER):
	    sys.exit("not signed: " + sys.argv[1])
	sig_len = int.from_bytes(data[-len(MARKER) - 4:-len(MARKER)], "big")
	with open(sys.argv[2], "wb") as f:
	    f.write(data[:len(data) - len(MARKER) - 12 - sig_len])
	fd = os.open(sys.argv[2], os.O_RDONLY)
	libc = ctypes.CDLL(None, use_errno=True)
	ret = libc.syscall(FINIT_MODULE[platform.machine()], fd, b"", 0)
	print("done" if ret == 0 else errno.errorcode[ctypes.get_errno()])
	PY
	grep -qx EPERM "$W/module" &&
	[ "$(counter ModuleSignature)" -gt "$now" ]
'

if [ -e /proc/kcore ]; then
	test_expect_success '/proc/kcore is refused and counted' '
		now=$(counter Kcore) &&
		[ "$(open_errno /proc/kcore)" = EPERM ] &&
		[ "$(counter Kcore)" -gt "$now" ]
	'
fi
CONFIG=$(ls /sys/bus/pci/devices/*/config 2>/dev/null | head -1)
if [ -n "$CONFIG" ]; then
	# The interrupt line byte written back as it is, should the write pass.
	test_expect_success 'a PCI config write is refused and counted' '
		now=$(counter PciAccess) &&
		python3 - "$CONFIG" >"$W/pci" <<-\PY &&
		import errno, sys
		with open(sys.argv[1], "r+b", buffering=0) as f:
		    f.seek(0x3c)
		    line = f.read(1)
		    f.seek(0x3c)
		    try:
		        f.write(line)
		        print("done")
		    except OSError as e:
		        print(errno.errorcode[e.errno])
		PY
		grep -qx EPERM "$W/pci" &&
		[ "$(counter PciAccess)" -gt "$now" ]
	'
fi
if [ -e /dev/mem ]; then
	test_expect_success '/dev/mem is refused' '
		[ "$(open_errno /dev/mem)" = EPERM ]
	'
fi
test_expect_success 'reading /sys/power/state counts nothing' '
	now=$(counter total) &&
	cat /sys/power/state >/dev/null 2>&1 || :
	[ "$(counter total)" -eq "$now" ]
'
test_expect_success 'status lists the integrity counters apart from the tamper counters' '
	"$SHIRUDO_BIN" status >"$W/status" &&
	sed -n "/^Integrity attempts (this boot):/,/^\$/p" "$W/status" \
		>"$W/integrity" &&
	grep -q "^  ModuleSignature  *[1-9][0-9]*  module load without" \
		"$W/integrity" &&
	! sed -n "/^Tamper attempts (this boot):/,/^\$/p" "$W/status" |
		grep -q "ModuleSignature"
'
test_expect_success 'the keepalive carries every integrity counter in order' '
	"$SHIRUDO_BIN" status --keepalive | python3 -c "
import json, sys
body = json.load(sys.stdin)
integrity = body[\"integrity\"]
assert len(integrity) == 22 and integrity[0] > 0, integrity
assert body[\"flags\"] & 64 == 0, body[\"flags\"]
"
'
test_expect_success 'root cannot open the integrity counter map' '
	[ "$(open_errno /run/shirudo/bpffs/integrity)" = EACCES ]
'
test_done
