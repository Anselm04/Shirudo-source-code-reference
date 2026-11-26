#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6137 -- no traced task can exec shirudo, so no tracer carries over
# into it; the seal's exec check refuses it with EACCES and counts it as
# ExecTraced. The traced exec is of the runtime binary itself, not of the
# wrapper script that starts it.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
ENV=$(command -v env) || test_skip_all "no env"
BIN=$(runtime_binary)
[ -x "$BIN" ] || test_skip_all "cannot find the runtime shirudo"

# Exec $@ in a child that asked to be traced: print the errno of a
# refused exec, or "ran" once the child stopped at the exec and was let go.
traced_exec() {
	python3 - "$@" <<'EOF'
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
PTRACE_TRACEME, PTRACE_DETACH = 0, 17
pid = os.fork()
if pid == 0:
    libc.ptrace(PTRACE_TRACEME, 0, None, None)
    try:
        os.execv(sys.argv[1], sys.argv[1:])
    except OSError as e:
        os.write(1, b"%d\n" % e.errno)
    os._exit(0)
_, status = os.waitpid(pid, 0)
if os.WIFSTOPPED(status):
    libc.ptrace(PTRACE_DETACH, pid, None, None)
    os.waitpid(pid, 0)
    print("ran")
EOF
}

counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
print(json.load(sys.stdin)["tamper_attempts"]["counters"][sys.argv[1]])
' "$1"
}

test_expect_success 'a traced task execs an ordinary program' '
	[ "$(traced_exec "$ENV" true)" = ran ]
'

test_expect_success 'a traced task cannot exec shirudo, and the refusal is counted' '
	before=$(counter ExecTraced) &&
	out=$(traced_exec "$BIN" version) &&
	[ "$out" = 13 ] || {
		echo "traced exec of $BIN: ${out:-no outcome}"
		false
	} &&
	[ "$(counter ExecTraced)" = $((before + 1)) ]
'

test_expect_success 'shirudo still runs untraced' '
	"$SHIRUDO_BIN" version >/dev/null
'

test_done
