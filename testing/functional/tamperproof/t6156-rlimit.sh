#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6156 -- the kernel signals a command by the limits and interval timers
# it runs with, and no hook sees those signals: a command lifts its file
# size and CPU time limits and disarms its interval timers when it
# starts, and root cannot change the limits of one that runs, which
# counts as SealRlimit. Counters are read while no command holds the
# config lock.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
W=$(mktemp -d) || test_skip_all "cannot make a scratch directory"
PID=
cleanup() {
	if [ -n "$PID" ] && [ -d "/proc/$PID" ]; then
		fifo_release "$W/fifo" || :
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
# Wait for pid $1 to be shirudo asleep, as a command blocked on its fifo.
sleeping() {
	i=0
	while [ "$i" -lt 50 ]; do
		[ -d "/proc/$1" ] || return 1
		[ "$(awk '{print $2 $3}' "/proc/$1/stat" 2>/dev/null)" = "(shirudo)S" ] &&
			return 0
		sleep 0.1
		i=$((i + 1))
	done
	return 1
}
before=$(counter SealRlimit) || test_skip_all "no tamper counters"
mkfifo "$W/fifo" || test_skip_all "cannot make a fifo"

test_expect_success 'a command writes past the file size limit it was given' '
	(ulimit -f 1 && "$SHIRUDO_BIN" status --json >"$W/status.json") &&
	[ "$(wc -c <"$W/status.json")" -gt 4096 ]
'
test_expect_success 'root cannot change the limits of a running command' '
	"$SHIRUDO_BIN" bpm info "$W/fifo" >/dev/null 2>&1 &
	PID=$! &&
	sleeping "$PID" &&
	python3 -c "
import errno, resource, sys
try:
    resource.prlimit(int(sys.argv[1]), resource.RLIMIT_FSIZE, (1, 1))
    sys.exit(1)
except OSError as e:
    sys.exit(0 if e.errno == errno.EPERM else 2)
" "$PID" &&
	fifo_release "$W/fifo" &&
	{ wait "$PID" || :; } &&
	PID= &&
	[ "$(counter SealRlimit)" -gt "$before" ]
'
test_expect_success 'an interval timer set before exec does not stop it' '
	python3 - "$SHIRUDO_BIN" "$W/fifo" <<-\PY &&
	import os, signal, subprocess, sys, time
	child = subprocess.Popen(
	    [sys.argv[1], "bpm", "info", sys.argv[2]],
	    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
	    preexec_fn=lambda: signal.setitimer(signal.ITIMER_REAL, 0.3))
	time.sleep(1.5)
	alive = child.poll() is None
	fd = os.open(sys.argv[2], os.O_WRONLY | os.O_NONBLOCK)
	os.close(fd)
	child.wait()
	sys.exit(0 if alive and child.returncode != -signal.SIGALRM else 1)
	PY
	:
'
test_done
