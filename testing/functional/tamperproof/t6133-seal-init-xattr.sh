#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6133 -- labelling at creation (bpf/seal.c inode_init_security): an
# inode the runtime creates under a labelled directory the seal has seen
# is born with the label, before userspace could set it, and is sealed
# from that instant. The creator is the policy probe in the runtime
# image, which also removes what it made; root may create nothing there.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

: "${SHIRUDO_TEST_RUNTIME_PROBE:=/run/shirudo/runtime/usr/bin/shirudo-policy-probe}"
P=$SHIRUDO_TEST_RUNTIME_PROBE
LABEL=94442b45cfcdc59aabc2a91364ed2ae129418e05a5c1985231b9c032e673f469
DIR=/var/lib/shirudo/t6133.$(cat /proc/sys/kernel/random/uuid)
OUTSIDE=/root/t6133.$$
[ -x "$P" ] || test_skip_all "no policy probe in the runtime image"
[ -e /run/shirudo/bpffs/seal_inode_init_security_link ] ||
	test_skip_all "the seal does not label at creation on this target"

# Under the library's errexit a failing step would end the cleanup.
cleanup() {
	"$P" unlink "$DIR/sub/child" 2>/dev/null || true
	"$P" rmdir "$DIR/sub" 2>/dev/null || true
	"$P" unlink "$DIR/link" 2>/dev/null || true
	"$P" unlink "$DIR/file" 2>/dev/null || true
	"$P" rmdir "$DIR" 2>/dev/null || true
	rm -f "$OUTSIDE" 2>/dev/null || true
}
trap cleanup EXIT

label_of() {
	python3 -c '
import errno, os, sys
try:
    print(os.getxattr(sys.argv[1], "security.bpf.shirudo",
                      follow_symlinks=False).decode())
except OSError as e:
    print("unsupported" if e.errno == errno.EOPNOTSUPP else "none")' "$1"
}

labelled() {
	for f in "$@"; do
		[ "$(label_of "$f")" = "$LABEL" ] || {
			echo "$f: label $(label_of "$f")"
			return 1
		}
	done
}

if [ "$(label_of /run/shirudo)" = unsupported ]; then
	echo "# SKIP /run does not support security xattrs"
else
	test_expect_success 'the run directory carries the label' '
		labelled /run/shirudo
	'
fi

# Opening the state root records its mark for inode_init_security.
test_expect_success 'a directory the runtime makes in sealed state is born labelled' '
	ls /var/lib/shirudo >/dev/null &&
	"$P" mkdir "$DIR" &&
	labelled "$DIR"
'

test_expect_success 'and so is what it creates in there, without a reopen' '
	"$P" create "$DIR/file" &&
	"$P" symlink file "$DIR/link" &&
	"$P" mkdir "$DIR/sub" &&
	"$P" create "$DIR/sub/child" &&
	labelled "$DIR/file" "$DIR/link" "$DIR/sub" "$DIR/sub/child"
'

test_expect_success 'root can neither write, unlink nor rename any of it' '
	! sh -c "echo x >\"$DIR/file\"" 2>/dev/null &&
	! rm -f "$DIR/file" 2>/dev/null &&
	! mv "$DIR/file" "$DIR/moved" 2>/dev/null &&
	! rm -f "$DIR/link" 2>/dev/null &&
	! rm -f "$DIR/sub/child" 2>/dev/null &&
	[ -e "$DIR/file" ] && [ ! -s "$DIR/file" ] && [ -L "$DIR/link" ]
'

test_expect_success 'nor create anything beside it' '
	! touch "$DIR/root-file" 2>/dev/null &&
	! mkdir "$DIR/root-dir" 2>/dev/null &&
	! ln -s file "$DIR/root-link" 2>/dev/null &&
	[ ! -e "$DIR/root-file" ] && [ ! -e "$DIR/root-dir" ] &&
	[ ! -L "$DIR/root-link" ]
'

test_expect_success 'nor open an O_TMPFILE in it for writing' '
	! python3 -c "import os,sys; os.open(sys.argv[1], os.O_TMPFILE | os.O_WRONLY, 0o600)" \
	    "$DIR" 2>/dev/null
'

test_expect_success 'what the runtime creates outside the tree stays unlabelled' '
	"$P" create "$OUTSIDE" &&
	[ "$(label_of "$OUTSIDE")" = none ] &&
	rm -f "$OUTSIDE"
'

test_expect_success 'the runtime removes what it made' '
	"$P" unlink "$DIR/sub/child" &&
	"$P" rmdir "$DIR/sub" &&
	"$P" unlink "$DIR/link" &&
	"$P" unlink "$DIR/file" &&
	"$P" rmdir "$DIR" &&
	[ ! -e "$DIR" ]
'

test_done
