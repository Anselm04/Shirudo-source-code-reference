#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6102 -- the signature gate (the trust boundary): a .upatch signed by
# a cert that is NOT in the target's sealed "shirudo" keyring is rejected
# at BPF_PROG_LOAD. Mints a throwaway foreign key/cert (never genkey,
# which would clobber the operator key), builds a foreign-signed upatch,
# and confirms the load fails. Non-destructive (the load is refused).

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
FOREIGN="$FIXTURES/shirudo-test-foreign.upatch"
[ -s "$FOREIGN" ] || test_skip_all "missing prebuilt foreign fixture"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

test_expect_success 'foreign-signed upatch is rejected (cert not in keyring)' '
	$SHIRUDO_BIN upatch load "$FOREIGN" --no-precheck \
	    --report=- >"$WORK/out" 2>/dev/null || true
	res=$(report_field result <"$WORK/out") &&
	cat=$(report_field category <"$WORK/out") &&
	[ "$res" = "failed" ] &&
	{ [ "$cat" = "keyring_missing" ] || [ "$cat" = "signature_rejected" ]; }
'

test_done
