#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t5008 -- a line of a settings file is a line: one longer than its
# reader's buffer is not taken as two, and one holding a NUL is not
# taken for its prefix. fgets cut a long registry definition into two
# that each parsed, so a junk line could carry a key_file, and a NUL in
# the last line of the bootstrap settings left a cut value in effect.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

H=${SHIRUDO_TEST_IMAGE_CONFIG_HELPER:-./helper/test-image-config}
C=./helper/test-image-cli
[ -x "$H" ] && [ -x "$C" ] || test_skip_all "image helpers not built"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

root=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
printf "runtime.image = /var/lib/shirudo/runtime\nruntime.root_hash = %s\n" \
	"$root" >"$WORK/initrd.conf"

test_expect_success 'a NUL in the last bootstrap line is no cut value' '
	printf "config.image = /var/lib/shirudo/images/initial\nconfig.pcr = 15\nconfig.verification_key = /run/shirudo/runtime/etc/shirudo/c.der" \
		>"$WORK/clean.conf" &&
	"$H" bootstrap "$WORK/initrd.conf" "$WORK/clean.conf" >/dev/null &&
	python3 -c "import sys; d = open(sys.argv[1], \"rb\").read(); open(sys.argv[2], \"wb\").write(d.replace(b\"c.der\", b\"c\\0x.der\"))" \
		"$WORK/clean.conf" "$WORK/nul.conf" &&
	! "$H" bootstrap "$WORK/initrd.conf" "$WORK/nul.conf" >"$WORK/nul.out" &&
	grep -qx "rc=-22" "$WORK/nul.out"
'

ROOT="$WORK/config"
mkdir -p "$ROOT/etc/shirudo/bpm/registries.d" "$ROOT/etc/shirudo/bpm/keys"
printf "eventlog.max_bytes = 0\n" >"$ROOT/etc/shirudo/shirudo.conf"
printf "authenticated-key\n" >"$ROOT/etc/shirudo/bpm/keys/repo.der"
printf "substituted-key\n" >"$ROOT/etc/shirudo/bpm/keys/other.der"

test_expect_success 'a registry definition is read whole' '
	printf "endpoint = oci://example.invalid\nkey_file = etc/shirudo/bpm/keys/repo.der\n" \
		>"$ROOT/etc/shirudo/bpm/registries.d/plain.conf" &&
	"$C" "$ROOT" source plain >"$WORK/plain" &&
	grep -qx authenticated-key "$WORK/plain"
'

test_expect_success 'a line longer than the reader takes is not two lines' '
	python3 -c "import sys; open(sys.argv[1], \"w\").write(\"endpoint = oci://example.invalid\nkey_file = etc/shirudo/bpm/keys/repo.der\n\" + \"x\" * (4096 - 1) + \"key_file = etc/shirudo/bpm/keys/other.der\n\")" \
		"$ROOT/etc/shirudo/bpm/registries.d/long.conf" &&
	! "$C" "$ROOT" source long >"$WORK/long" 2>&1 &&
	! grep -q substituted-key "$WORK/long"
'

test_done
