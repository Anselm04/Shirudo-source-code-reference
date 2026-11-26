#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1002 -- removed fleet-management commands are absent from the CLI.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

SHIRUDO=../shirudo
W=$(mktemp -d) || exit 1
trap 'rm -rf "$W"' EXIT

test_expect_success 'fleet-management commands are absent from help' '
	commands=$($SHIRUDO help --list-cmds) &&
	! printf "%s\n" "$commands" | grep -Eq "^(nodes|rollout|remote)$" &&
	out=$($SHIRUDO --help 2>&1) &&
	! printf "%s\n" "$out" | grep -Eq "(nodes|rollout|remote)"
'

test_expect_success 'removed fleet-management commands are rejected' '
	for command in nodes rollout remote
	do
		! $SHIRUDO "$command" >"$W/out" 2>&1 &&
		grep -q "is not a shirudo command" "$W/out" || return 1
	done
'

test_done
