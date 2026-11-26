#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6129 -- a sealed keyring must hold exactly the certificates init
# enrolled. On a private keyring standing in for the bpf one, init
# refuses a foreign key, a nested keyring and a restriction it did not
# install, and the exact check counts every link, including a key that
# cannot be described.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

H=./helper/test-keyring-seal
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
[ -x "$H" ] || test_skip_all "missing $H"
[ -s "$FIXTURES/cert.der" ] && [ -s "$FIXTURES/own.der" ] ||
	test_skip_all "missing certificate fixtures"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
mkdir "$W/keys" "$W/revoked" &&
	cp "$FIXTURES/cert.der" "$W/keys/cert.der" || exit 1

run() {
	"$H" "$1" "$W/keys" "$W/revoked" "$FIXTURES/own.der"
}

test_expect_success 'the exact check counts every link of a keyring' '
	run exact
'

test_expect_success 'init enrols and seals, then finds the keyring sealed' '
	run fresh
'

test_expect_success 'init refuses a key linked before its seal' '
	run foreign
'

test_expect_success 'init refuses a nested keyring linked before its seal' '
	run nested
'

test_expect_success 'init refuses a restriction it did not install' '
	run restricted
'

test_expect_success 'init reports a keyring the kernel sealed empty' '
	run empty
'

test_done
