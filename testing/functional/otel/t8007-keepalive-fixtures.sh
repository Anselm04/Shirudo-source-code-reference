#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t8007 -- the keepalive fixtures agree with each other: every digest, root,
# set hash, mask and tree key of testing/fixtures/keepalive/ recomputes from
# the example tree.

cd "$(dirname "$0")/../.."
. ./test-lib.sh
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

test_expect_success 'every keepalive fixture value recomputes from the tree' '
	python3 fixtures/keepalive/recompute.py >&2
'

test_done
