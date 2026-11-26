#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3013 -- kprobe.multi and kretprobe.multi sections record their exact
# function list, sorted, in the signed attach metadata, and anything else
# is refused at build time.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

SHB=../tools/shirudo-build/shirudo-build
CHECK=helper/test-upatch-prog-metadata

command -v cc >/dev/null 2>&1 || test_skip_all "no C compiler"
command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built (make shirudo-build)"
[ -x "$CHECK" ] || test_skip_all "metadata helper not built"
[ -e ../vendor/linux/vmlinux.h ] || test_skip_all "no vendor/linux/vmlinux.h (build the tree)"
[ -e ../vendor/libbpf/bpf/bpf_helpers.h ] || test_skip_all "no vendored bpf headers"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# shirudo signs with ML-DSA-87 only (needs OpenSSL >= 3.5 to mint it).
openssl req -x509 -newkey ML-DSA-87 -nodes -keyout "$WORK/k.pem" \
	-outform DER -out "$WORK/c.der" -days 1 -subj "/CN=t3013" \
	>/dev/null 2>&1 || test_skip_all "openssl ML-DSA keygen failed (needs OpenSSL >= 3.5)"

case "$SHB" in
/*) B="$SHB" ;;
*)  B="$(pwd)/$SHB" ;;
esac

# Builds SEC("$1") into $WORK/probe.upatch; the build log is $WORK/log.
build_section() {
	cat > "$WORK/probe.bpf.c" <<EOF
// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("$1")
int probe(struct pt_regs *ctx)
{
	return 0;
}
EOF
	( cd .. && "$B" "$WORK/probe.bpf.c" -o "$WORK/probe.upatch" \
		--vmlinux vendor/linux/vmlinux.h --name kprobe-multi-test \
		--key "$WORK/k.pem" --cert "$WORK/c.der" ) >"$WORK/log" 2>&1
}

test_expect_success 'kprobe.multi signs its names sorted' '
	build_section "kprobe.multi/vfs_write,vfs_read,ksys_read" &&
	"$CHECK" "$WORK/probe.upatch" kprobe-multi ksys_read,vfs_read,vfs_write
'

test_expect_success 'a uprobe beside a kprobe.multi keeps both target blocks' '
	cat > "$WORK/target.c" <<-\EOF &&
	__attribute__((noinline, used)) int fooFunc(int value) { return value + 1; }
	int main(void) { return fooFunc(1); }
	EOF
	cc -O0 -g -Wl,--build-id=sha1 -o "$WORK/target" "$WORK/target.c" &&
	cat > "$WORK/mixed.bpf.c" <<-EOF &&
	// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
	#include "vmlinux.h"
	#include <bpf/bpf_helpers.h>

	char _license[] SEC("license") = "Dual BSD/GPL";

	SEC("uprobe/$WORK/target:fooFunc")
	int user_probe(struct pt_regs *ctx)
	{
		return 0;
	}

	SEC("kprobe.multi/vfs_write,vfs_read")
	int kernel_probe(struct pt_regs *ctx)
	{
		return 0;
	}
	EOF
	( cd .. && "$B" "$WORK/mixed.bpf.c" -o "$WORK/mixed.upatch" \
		--vmlinux vendor/linux/vmlinux.h --name kprobe-multi-mixed \
		--key "$WORK/k.pem" --cert "$WORK/c.der" ) >"$WORK/log" 2>&1 &&
	"$CHECK" "$WORK/mixed.upatch" uprobe-kprobe-multi "$WORK/target" \
		vfs_read,vfs_write
'

test_expect_success 'kretprobe.multi records the return kind' '
	build_section "kretprobe.multi/vfs_read" &&
	"$CHECK" "$WORK/probe.upatch" kretprobe-multi vfs_read
'

test_expect_success 'a section without a list is refused' '
	! build_section "kprobe.multi" &&
	grep -q "unsupported kprobe section" "$WORK/log" &&
	! build_section "kretprobe.multi/" &&
	grep -q "unsupported kprobe section" "$WORK/log"
'

test_expect_success 'a glob is refused with an actionable error' '
	! build_section "kprobe.multi/vfs_*" &&
	grep -q "globs are unsupported" "$WORK/log"
'

test_expect_success 'a function named twice is refused' '
	! build_section "kprobe.multi/vfs_read,vfs_read" &&
	grep -q "named twice" "$WORK/log"
'

test_expect_success 'an empty list element is refused' '
	! build_section "kprobe.multi/vfs_read,,vfs_write" &&
	grep -q "invalid kprobe multi section" "$WORK/log"
'

test_expect_success 'a name of KSYM_NAME_LEN bytes is refused' '
	long=$(printf "%512s" "" | tr " " a) &&
	! build_section "kprobe.multi/$long" &&
	grep -q "invalid kprobe multi section" "$WORK/log"
'

test_expect_success 'kprobe.session stays refused' '
	! build_section "kprobe.session/vfs_read" &&
	grep -q "unsupported section" "$WORK/log"
'

test_done
