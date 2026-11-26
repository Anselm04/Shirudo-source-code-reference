#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6110 -- non-shirudo callers cannot change executable identity with
# PR_SET_MM.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

python3 -c '
import sys
status = open("/proc/self/status", encoding="ascii").read().splitlines()
caps = next(line.split()[1] for line in status if line.startswith("CapEff:"))
sys.exit(0 if int(caps, 16) & (1 << 24) else 1)
' || test_skip_all "CAP_SYS_RESOURCE unavailable"

test_expect_success 'PR_SET_MM executable changes require shirudo identity' '
	python3 functional/tamperproof/t6110-pr-set-mm-identity.py "$SHIRUDO_BIN"
'

test_done
