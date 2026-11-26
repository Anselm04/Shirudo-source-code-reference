#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6118 -- entries root brings into sealed state. A sealed directory
# takes new entries from shirudo alone: a file, directory, symbolic link
# or device root creates there is refused, and so is a rename or hard
# link, which would bring an inode in with its contents. The seal reads
# the directory's label in the hook, so evicting the directory's mark
# opens nothing either, and a re-run of init completes unchanged.
# Non-destructive.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-scope-kprobe
LOAD="$FIXTURES/$NAME.upatch"
S=/var/lib/shirudo
ARCHIVE=$S/upatches
STAGE=/var/lib/t6118-stage
PIN="/run/shirudo/bpffs/upatches/$NAME/link"
[ -s "$LOAD" ] || test_skip_all "missing scope fixture"
[ ! -e "$PIN" ] || test_skip_all "$NAME is loaded"
[ -d "$ARCHIVE" ] || test_skip_all "no archive at $ARCHIVE"

# Under the library's errexit a failing step would end the cleanup.
restore() {
	rm -f "$ARCHIVE/t6118.upatch" "$ARCHIVE/t6118-link.upatch" \
		"$ARCHIVE/t6118-linked.upatch" "$S/t6118-link" \
		2>/dev/null || true
	rmdir "$S/t6118-dir" 2>/dev/null || true
	rm -rf "$STAGE"
}
trap restore EXIT

counter() {
	"$SHIRUDO_BIN" status --json 2>/dev/null |
		python3 -c "import json,sys; print(json.load(sys.stdin)[\"tamper_attempts\"][\"counters\"][\"SealEntry\"])"
}

chain() {
	"$SHIRUDO_BIN" status --json 2>/dev/null |
		python3 -c "import json,sys; print(json.load(sys.stdin)[\"tpm\"][\"chain\"])"
}

labelled() {
	python3 -c "import os,sys
try:
    os.getxattr(sys.argv[1], \"security.bpf.shirudo\", follow_symlinks=False)
except OSError:
    sys.exit(1)" "$1"
}

# Rename while the directory's mark is evicted: the seal reads the
# label, so every try is refused.
plant() {
	i=0
	while [ "$i" -lt 8 ]; do
		sync && echo 2 >/proc/sys/vm/drop_caches &&
			mv "$1" "$2" 2>/dev/null && return 0
		i=$((i + 1))
	done
	return 1
}

CHAIN=$(chain)

test_expect_success 'root cannot create a file, a directory or a symbolic link in sealed state' '
	before=$(counter) &&
	! touch "$ARCHIVE/t6118.upatch" 2>/dev/null &&
	! mkdir "$S/t6118-dir" 2>/dev/null &&
	! ln -s /tmp "$S/t6118-link" 2>/dev/null &&
	[ ! -e "$ARCHIVE/t6118.upatch" ] && [ ! -e "$S/t6118-dir" ] &&
	[ ! -L "$S/t6118-link" ] &&
	[ "$(counter)" -ge $((before + 3)) ]
'

test_expect_success 'root cannot rename or hard-link content into sealed state' '
	before=$(counter) &&
	mkdir -p "$STAGE" && cp "$LOAD" "$STAGE/t6118.upatch" &&
	! mv "$STAGE/t6118.upatch" "$ARCHIVE/t6118.upatch" 2>/dev/null &&
	! ln "$STAGE/t6118.upatch" "$ARCHIVE/t6118-linked.upatch" 2>/dev/null &&
	[ ! -e "$ARCHIVE/t6118.upatch" ] &&
	[ ! -e "$ARCHIVE/t6118-linked.upatch" ] &&
	[ -s "$STAGE/t6118.upatch" ] &&
	[ "$(counter)" -ge $((before + 2)) ]
'

# A link to a signed artifact root keeps elsewhere cannot slip in even
# while the directory's mark is evicted.
test_expect_success 'a link cannot slip in while the directory mark is evicted' '
	before=$(counter) &&
	mkdir -p "$STAGE" && cp "$LOAD" "$STAGE/$NAME.upatch" &&
	ln -s "$STAGE/$NAME.upatch" "$STAGE/t6118-link.upatch" &&
	! plant "$STAGE/t6118-link.upatch" "$ARCHIVE/t6118-link.upatch" &&
	[ ! -L "$ARCHIVE/t6118-link.upatch" ] &&
	[ "$(counter)" -gt "$before" ] &&
	"$SHIRUDO_BIN" init >/dev/null 2>&1 &&
	[ ! -e "$PIN" ] &&
	[ "$(chain)" = "$CHAIN" ]
'

test_done
