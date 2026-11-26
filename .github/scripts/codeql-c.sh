#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/codeql-c.sh -- the C build CodeQL traces, on Debian
# testing with what debian-deps.sh installs. prepare runs before the
# tracing starts and builds what is not shirudo's own, the vendored
# libbpf, and the vmlinux.h its BPF programs include; build then compiles
# shirudo's sources alone: the binary with its BPF objects, the
# shirudo-build helper, the quote checker, the test helpers and the unit
# tests.
#
#   .github/scripts/codeql-c.sh prepare <vmlinux-btf>
#   .github/scripts/codeql-c.sh build <vmlinux-btf>
#
# Run as root in the checkout root, inside a throwaway container.

set -eu

if [ "$#" -ne 2 ]; then
	printf 'usage: %s prepare|build <vmlinux-btf>\n' "$0" >&2
	exit 2
fi
export BPF_VMLINUX_BTF="$2"

case $1 in
prepare)
	grep -aq 'signature_size' "$BPF_VMLINUX_BTF" || {
		echo "$BPF_VMLINUX_BTF lacks bpf_attr.signature_size; needs a signed-BPF capable bpf-next kernel" >&2
		exit 1
	}
	sh .github/scripts/debian-deps.sh
	make config
	make -f Makefile.shirudo PROFILE=operator CONFIG_MK=config.mk \
		vendor/libbpf/libbpf.a vendor/linux/vmlinux.h
	;;
build)
	make -j"$(nproc)"
	make shirudo-build
	make quote-check
	make -C testing test-helpers build-unit
	;;
*)
	printf 'usage: %s prepare|build <vmlinux-btf>\n' "$0" >&2
	exit 2
	;;
esac
