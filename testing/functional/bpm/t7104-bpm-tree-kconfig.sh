#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7104 -- a kconfig selector the target cannot read stops the sync where
# it is; once the config reads, the operation applies.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
REGISTRY="$FIXTURES/tree-oci"
TREE_REPO="$REGISTRY/shirudo/upatch-tree"
MATCH_PIN=/run/shirudo/bpffs/upatches/shirudo-test-tree-match/link
PROC=/proc/config.gz
CONFIG="/boot/config-$(uname -r)"
WORK=$(mktemp -d)
PROC_BOUND=0
CONFIG_BOUND=0
CONFIG_MADE=0

for fixture in \
	"$TREE_REPO/manifests/kconfig" \
	"$FIXTURES/shirudo-test-tree-match.upatch" \
	"$FIXTURES/shirudo-test-tree-match.unload.upatch" \
	"$FIXTURES/cert.der" \
	"./helper/test-oci-registry.py"
do
	[ -s "$fixture" ] || test_skip_all "missing tree fixture: $fixture"
done

[ "$(tree_state_field tree_id)" = shirudo-test-tree ] &&
	[ "$(tree_state_field last_seq)" = 5 ] ||
	test_skip_all "tree state is not where t7103 leaves it"

# What the kernel shows as its config, in /proc and in /boot, is the
# test's own file for the duration.
clear_config()
{
	[ "$PROC_BOUND" -eq 0 ] || umount "$PROC"
	PROC_BOUND=0
	[ "$CONFIG_BOUND" -eq 0 ] || umount "$CONFIG"
	CONFIG_BOUND=0
	[ "$CONFIG_MADE" -eq 0 ] || rm -f "$CONFIG"
	CONFIG_MADE=0
}

make_socket()
{
	python3 -c "
import socket, sys
socket.socket(socket.AF_UNIX).bind(sys.argv[1])
" "$1"
}

# A socket in the config's place: its open fails with ENXIO, a read
# error rather than a missing config.
show_socket()
{
	clear_config
	make_socket "$WORK/socket"
	if [ -e "$PROC" ]; then
		mount --bind "$WORK/socket" "$PROC"
		PROC_BOUND=1
	fi
	if [ -e "$CONFIG" ]; then
		mount --bind "$WORK/socket" "$CONFIG"
		CONFIG_BOUND=1
	else
		make_socket "$CONFIG"
		CONFIG_MADE=1
	fi
}

# A config the selector of operation 6 matches.
show_matching()
{
	clear_config
	printf 'CONFIG_BPF=y\n' >"$WORK/config"
	if [ -e "$PROC" ]; then
		mount --bind "$WORK/config" "$PROC"
		PROC_BOUND=1
	fi
	if [ -e "$CONFIG" ]; then
		mount --bind "$WORK/config" "$CONFIG"
		CONFIG_BOUND=1
	else
		cp "$WORK/config" "$CONFIG"
		CONFIG_MADE=1
	fi
}

cleanup()
{
	tree_registry_stop
	clear_config || true
	if [ -e "$MATCH_PIN" ]; then
		"$SHIRUDO_BIN" upatch unload \
			"$FIXTURES/shirudo-test-tree-match.unload.upatch" \
			--no-precheck >/dev/null 2>&1 || true
	fi
	tree_cleanup_config
	rm -rf "$WORK"
}
trap cleanup EXIT

tree_configure kconfig
tree_registry_start "$REGISTRY" "$WORK"
show_socket

test_expect_success 'a config that cannot be read stops the sync on the operation' '
	require_loaded shirudo-test-tree-match &&
	! BPM_OCI_SCHEME=http "$SHIRUDO_BIN" bpm tree sync \
		--report "$WORK/stopped.json" >/dev/null 2>"$WORK/stopped.err" &&
	grep -q "phase=selector_evaluate seq=6 " "$WORK/stopped.err" &&
	[ ! -e "$WORK/stopped.json" ] &&
	[ "$(tree_state_field last_seq)" = 5 ] &&
	[ -e "$MATCH_PIN" ]
'

show_matching

test_expect_success 'the operation applies once the config can be read' '
	tree_sync "$WORK/applied.json" &&
	[ "$(report_field selected <"$WORK/applied.json")" = 1 ] &&
	[ "$(report_field applied <"$WORK/applied.json")" = 1 ] &&
	[ "$(report_field last_seq <"$WORK/applied.json")" = 6 ] &&
	[ ! -e "$MATCH_PIN" ]
'

test_done
