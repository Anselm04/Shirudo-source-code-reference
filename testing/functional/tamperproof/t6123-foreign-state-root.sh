#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6123 -- init labels the state tree on the run that brings enforcement
# up, and the label is what the seal takes for shirudo's own. A tree of
# root's bound over /var/lib/shirudo in a mount namespace of root's own
# carries no label, and a re-run of init there took it for a first run
# and labelled root's files, which the eviction gap then lets root bring
# into sealed state as shirudo's. With enforcement live, init must refuse
# such a tree and label nothing in it; the real tree stays as it was.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v unshare >/dev/null 2>&1 || test_skip_all "no unshare"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
FIXTURE="$FIXTURES/shirudo-test-marker.upatch"
[ -s "$FIXTURE" ] || test_skip_all "missing marker fixture"
W=/tmp/t6123
rm -rf "$W"
mkdir -p "$W/upatches"
cp "$FIXTURE" "$W/upatches/t6123.upatch"
cp /var/lib/shirudo/eventlog "$W/eventlog" 2>/dev/null || true
trap 'rm -rf "$W"' EXIT

labelled() {
	python3 -c "import os,sys
try:
    os.getxattr(sys.argv[1], \"security.bpf.shirudo\", follow_symlinks=False)
except OSError:
    sys.exit(1)" "$1"
}

test_expect_success 'init refuses a state root bound over the path without the label' '
	! unshare -m sh -c "mount --bind $W /var/lib/shirudo && $SHIRUDO_BIN init" \
		>/dev/null 2>&1 &&
	! labelled "$W" &&
	! labelled "$W/upatches" &&
	! labelled "$W/upatches/t6123.upatch"
'

test_expect_success 'init still completes on the sealed tree' '
	"$SHIRUDO_BIN" init >/dev/null 2>&1 &&
	labelled /var/lib/shirudo
'

test_done
