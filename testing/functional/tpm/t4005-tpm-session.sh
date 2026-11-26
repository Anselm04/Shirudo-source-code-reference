#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh

[ -x helper/tpmsim-cmd ] || test_skip_all "tpmsim-cmd not built (libtpms required)"
WORK=$(mktemp -d) || exit 1
cleanup() {
	for mode in unsalted-control nv-extend nv-replay pcr-extend nv-read \
		    pcr-read clock policy-digest identity evidence; do
		rm -f "$WORK/$mode/permanent" "$WORK/$mode/volatile" "$WORK/$mode/NVChip"
		rmdir "$WORK/$mode"
	done
	rm -f "$WORK/eventlog"
	rmdir "$WORK"
}
trap cleanup EXIT

for mode in unsalted-control nv-extend nv-replay pcr-extend nv-read \
	    pcr-read clock policy-digest identity; do
	export SHIRUDO_TPM_TCTI="cmd:exec $(pwd)/helper/tpmsim-cmd $WORK/$mode"
	test_expect_success "TPM session: $mode" '
		./helper/test-tpm-session "$mode"
	'
done

test_expect_success 'attest fails on an eventlog it cannot read to the end' '
	SHIRUDO_TPM_TCTI="cmd:exec $(pwd)/helper/tpmsim-cmd $WORK/evidence" \
	SHIRUDO_EVENTLOG_PATH="$WORK/eventlog" \
	SHIRUDO_EVENTLOG_PENDING_PATH="$WORK/eventlog.pending" \
		./helper/test-tpm-session evidence
'

test_done
