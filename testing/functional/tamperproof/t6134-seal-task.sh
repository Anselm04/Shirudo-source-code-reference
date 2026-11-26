#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6134 -- the seal's task hooks (bpf/seal.c ptrace_access_check and
# perf_event_alloc): a task that runs the runtime shirudo binary can
# neither be ptrace-attached, read through /proc nor have a perf event
# bound to it, even by root. Only an attach-mode access counts as
# SealPtrace; a read-mode one is refused uncounted. The task is a
# shirudo blocked on opening a fifo, released at the end.
# Non-destructive.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
[ -e /run/shirudo/bpffs/seal_ptrace_access_check_link ] ||
	test_skip_all "the seal's task hooks are not attached on this target"

W=$(mktemp -d) || test_skip_all "cannot make a scratch directory"
PID=
cleanup() {
	if [ -n "$PID" ]; then
		if [ -d "/proc/$PID" ] &&
			[ "$(awk '{print $3}' "/proc/$PID/stat" 2>/dev/null)" != Z ]; then
			fifo_release "$W/fifo" || :
		fi
		wait "$PID" 2>/dev/null || :
	fi
	rm -rf "$W"
}
trap cleanup EXIT

counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
print(json.load(sys.stdin)["tamper_attempts"]["counters"][sys.argv[1]])
' "$1"
}

# Counters are read while no command holds the config lock.
before=$(counter SealPtrace) || test_skip_all "no tamper counters"
mkfifo "$W/fifo" || test_skip_all "cannot make a fifo"
"$SHIRUDO_BIN" bpm info "$W/fifo" >/dev/null 2>&1 &
PID=$!
# A sleeping task may still be the shell that forks it, or completing
# TPM startup.
i=0
while [ "$i" -lt 50 ]; do
	[ -d "/proc/$PID" ] || break
	[ "$(awk '{print $2 $3}' "/proc/$PID/stat" 2>/dev/null)" = "(shirudo)S" ] &&
		break
	sleep 0.1
	i=$((i + 1))
done
[ -d "/proc/$PID" ] || test_skip_all "shirudo did not stay around"

# A /proc access by kind, against pid $2: 0 granted, 1 refused with
# EACCES, 3 refused otherwise. exe and environ are read-mode checks,
# mem an attach-mode one.
PROC='
import errno, os, sys
kind, pid = sys.argv[1], sys.argv[2]
try:
    if kind == "exe":
        os.readlink("/proc/%s/exe" % pid)
    else:
        os.close(os.open("/proc/%s/%s" % (pid, kind), os.O_RDONLY))
except OSError as e:
    sys.exit(1 if e.errno == errno.EACCES else 3)
'
# ptrace(PTRACE_ATTACH): 0 attached (and detached again), 1 refused by
# the seal, 3 refused otherwise.
ATTACH='
import ctypes, sys
libc = ctypes.CDLL(None, use_errno=True)
pid = int(sys.argv[1])
if libc.ptrace(16, pid, None, None) == 0:
    libc.ptrace(17, pid, None, None)
    sys.exit(0)
sys.exit(1 if ctypes.get_errno() == 13 else 3)
'
# perf_event_open(PERF_COUNT_SW_CPU_CLOCK) bound to a task: the same
# exit codes.
PERF='
import ctypes, os, struct, sys
nr = {"x86_64": 298, "aarch64": 241, "riscv64": 241}.get(os.uname().machine)
if nr is None:
    sys.exit(4)
libc = ctypes.CDLL(None, use_errno=True)
pid = os.getpid() if sys.argv[1] == "self" else int(sys.argv[1])
attr = ctypes.create_string_buffer(
    struct.pack("IIQQQQQQQ", 1, 64, 0, 0, 0, 0, 0, 0, 0), 64)
fd = libc.syscall(nr, attr, pid, -1, -1, 0)
if fd >= 0:
    os.close(fd)
    sys.exit(0)
sys.exit(1 if ctypes.get_errno() == 13 else 3)
'

# mm_access() grants CAP_PERFMON a read of environ and maps past the
# ptrace check unless mm_read_access refuses it (carried patch 0005).
test_expect_success 'root cannot read the exe link, environ or maps of a running shirudo' '
	for kind in exe environ maps; do
		python3 -c "$PROC" "$kind" "$PID"; rc=$?
		[ "$rc" = 1 ] || { echo "$kind: $rc" >&2; return 1; }
	done
'

test_expect_success 'root cannot ptrace-attach to a running shirudo' '
	python3 -c "$ATTACH" "$PID"; [ "$?" = 1 ]
'

test_expect_success 'nor open its /proc mem' '
	python3 -c "$PROC" mem "$PID"; [ "$?" = 1 ]
'


if python3 -c "$PERF" self 2>/dev/null; then
	test_expect_success 'root cannot bind a perf event to a running shirudo' '
		python3 -c "$PERF" "$PID"; [ "$?" = 1 ]
	'
else
	echo "# perf_event_open is unavailable here; the perf case is not run"
fi

# The task is the main shell's child: the case's subshell cannot reap it,
# so it watches the task become a zombie instead.
test_expect_success 'the task is unharmed and finishes once released' '
	[ -d "/proc/$PID" ] &&
	fifo_release "$W/fifo" &&
	i=0 &&
	while s=$(cut -d" " -f3 "/proc/$PID/stat" 2>/dev/null) &&
	      [ "$s" != Z ]; do
		i=$((i + 1))
		[ "$i" -lt 100 ] || return 1
		sleep 0.1
	done
'

test_expect_success 'the two attach-mode refusals alone count as SealPtrace' '
	[ "$(counter SealPtrace)" = "$((before + 2))" ]
'

test_done
