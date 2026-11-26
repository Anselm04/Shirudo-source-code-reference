#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/scan-build.sh -- build the binary, the shirudo-build
# helper and the quote checker under clang's static analyzer with its
# default checkers, on Debian testing with what debian-deps.sh installs,
# and fail on any finding. The analyzer follows the paths through each
# function and its callees in the file: a value stored and never read,
# a NULL or uninitialized one used, memory leaked or used after its
# free. The vendored libbpf is analyzed as it is built but not reported.
# The build is make ANALYZE=1, without the libc wrappers that hide from
# the analyzer which function a call makes. The HTML report goes to
# build/scan-build.
#
#   .github/scripts/scan-build.sh <vmlinux-btf>
#
# Run as root in the checkout root, inside a throwaway container.

set -eu

if [ "$#" -ne 1 ]; then
	printf 'usage: %s <vmlinux-btf>\n' "$0" >&2
	exit 2
fi
export BPF_VMLINUX_BTF="$1"

grep -aq 'signature_size' "$BPF_VMLINUX_BTF" || {
	echo "$BPF_VMLINUX_BTF lacks bpf_attr.signature_size; needs a signed-BPF capable bpf-next kernel" >&2
	exit 1
}
sh .github/scripts/debian-deps.sh
sh .github/scripts/install-clang.sh clang-tools-23

jobs=$(nproc)
scan-build-23 --status-bugs --use-cc=clang-23 --exclude vendor \
	-o build/scan-build \
	sh -c "make -j$jobs ANALYZE=1 && make ANALYZE=1 shirudo-build &&
		make ANALYZE=1 quote-check"
