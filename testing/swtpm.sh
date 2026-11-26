#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/swtpm.sh -- spin up a software TPM 2.0 (swtpm) on loopback for
# shirudo dev and CI, packaged so a single command brings the emulator
# up, prints the SHIRUDO_TPM_TCTI line to export, and tears it down.
#
# Usage:
#   testing/swtpm.sh start         # bring it up, print SHIRUDO_TPM_TCTI=...
#   testing/swtpm.sh stop          # stop the emulator (state kept)
#   testing/swtpm.sh status        # is it running? on which port?
#   testing/swtpm.sh clean         # stop + wipe the state dir (TPM reset)
#   testing/swtpm.sh env           # print the export line for the running one
#
# Env overrides (all optional):
#   SHIRUDO_SWTPM_STATE   state dir              (default /tmp/shirudo-swtpm)
#   SHIRUDO_SWTPM_PORT    TCP server port        (default 2321; ctrl = +1)
#   SHIRUDO_SWTPM_HOST    bind address           (default 127.0.0.1)
#
# Notes:
# - The server only ever binds to loopback. swtpm has no auth on its TCP
#   socket; do not expose it on a real interface.
# - "stop" leaves the state dir; a restart is a TPM reset, which clears
#   the per-boot measurement register the way a reboot does. "clean"
#   wipes the state (new endorsement and attestation keys).
# - shirudo's pre-flight skips the /dev/tpmrm0 check when SHIRUDO_TPM_TCTI
#   is set; shirudo has no unmeasured mode, so on a machine without a TPM
#   this emulator is the way to run it at all.

set -u

STATE="${SHIRUDO_SWTPM_STATE:-/tmp/shirudo-swtpm}"
PORT="${SHIRUDO_SWTPM_PORT:-2321}"
HOST="${SHIRUDO_SWTPM_HOST:-127.0.0.1}"
CTRL_PORT=$((PORT + 1))
PIDFILE="$STATE/swtpm.pid"
LOGFILE="$STATE/swtpm.log"
TCTI="swtpm:host=$HOST,port=$PORT"

die() { printf 'swtpm.sh: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1' -- install swtpm + swtpm-tools"; }

is_running() {
	local pid
	[ -s "$PIDFILE" ] || return 1
	pid=$(cat "$PIDFILE" 2>/dev/null) || return 1
	[ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

do_start() {
	need swtpm

	if is_running; then
		say "already running: pid $(cat "$PIDFILE"), TCTI $TCTI"
		say "export SHIRUDO_TPM_TCTI='$TCTI'"
		return 0
	fi

	mkdir -p "$STATE" || die "cannot create $STATE"
	chmod 0700 "$STATE"

	# EK/platform certs are nice-to-have (attest carries the EK cert
	# when present); if swtpm_setup is not installed, libtpms will
	# provision the basic TPM state on first --startup-clear.
	if [ ! -e "$STATE/tpm2-00.permall" ] && command -v swtpm_setup >/dev/null 2>&1; then
		swtpm_setup --tpm2 --tpm-state "$STATE" \
			--create-ek-cert --create-platform-cert \
			>"$STATE/setup.log" 2>&1 \
			|| { cat "$STATE/setup.log" >&2; die "swtpm_setup failed"; }
	fi

	# bindaddr= keeps the socket on loopback (swtpm defaults to 127.0.0.1
	# already, but be explicit -- a future swtpm default change must not
	# silently expose the emulator).
	swtpm socket --tpm2 \
		--tpmstate "dir=$STATE,mode=0700" \
		--server "type=tcp,bindaddr=$HOST,port=$PORT" \
		--ctrl   "type=tcp,bindaddr=$HOST,port=$CTRL_PORT" \
		--flags startup-clear \
		--log "file=$LOGFILE,level=20" \
		--pid "file=$PIDFILE" \
		--daemon \
		|| { [ -s "$LOGFILE" ] && tail -20 "$LOGFILE" >&2; die "swtpm failed to start"; }

	# --daemon returns once the parent forks; give the child a beat to
	# bind so the printed env line is usable immediately.
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		is_running && break
		sleep 0.1
	done
	is_running || { [ -s "$LOGFILE" ] && tail -20 "$LOGFILE" >&2; die "swtpm did not come up"; }

	say "swtpm up: pid $(cat "$PIDFILE"), state $STATE, $HOST:$PORT (ctrl :$CTRL_PORT)"
	say ""
	say "  export SHIRUDO_TPM_TCTI='$TCTI'"
	say ""
	say "Stop with:  testing/swtpm.sh stop"
	say "Reset NV:   testing/swtpm.sh clean"
}

do_stop() {
	if ! is_running; then
		say "not running"
		[ -e "$PIDFILE" ] && rm -f "$PIDFILE"
		return 0
	fi
	local pid
	pid=$(cat "$PIDFILE")
	kill "$pid" 2>/dev/null || true
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	if kill -0 "$pid" 2>/dev/null; then
		kill -KILL "$pid" 2>/dev/null || true
	fi
	rm -f "$PIDFILE"
	say "swtpm stopped (state kept at $STATE)"
}

do_status() {
	if is_running; then
		say "running:  pid $(cat "$PIDFILE")"
		say "state:    $STATE"
		say "listen:   $HOST:$PORT  (ctrl :$CTRL_PORT)"
		say "tcti:     $TCTI"
		say ""
		say "  export SHIRUDO_TPM_TCTI='$TCTI'"
	else
		say "not running"
		[ -d "$STATE" ] && say "state:    $STATE (preserved)"
		return 1
	fi
}

do_env() {
	is_running || die "swtpm not running (start it first: testing/swtpm.sh start)"
	printf "export SHIRUDO_TPM_TCTI='%s'\n" "$TCTI"
}

do_clean() {
	is_running && do_stop
	if [ -e "$STATE" ]; then
		rm -rf "$STATE" || die "could not remove $STATE"
		say "state wiped: $STATE"
	else
		say "nothing to clean"
	fi
}

case "${1:-}" in
start)		do_start ;;
stop)		do_stop ;;
status)		do_status ;;
env)		do_env ;;
clean)		do_clean ;;
-h|--help|help|"")
		sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//' ;;
*)		die "unknown command '$1' (try: start | stop | status | env | clean)" ;;
esac
