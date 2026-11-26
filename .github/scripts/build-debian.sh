#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/build-debian.sh -- build on a Debian testing container of
# any architecture, with what debian-deps.sh installs: the binary and the
# shirudo-build helper, then the unit tests and the linkage check. The BPF
# objects are bytecode whatever the host, so the BTF can come from a
# kernel of another architecture.
#
#   .github/scripts/build-debian.sh <vmlinux-btf>
#
# Run as root in the checkout root, inside a throwaway container: it
# installs packages and changes the git configuration.

set -eu

if [ "$#" -ne 1 ]; then
	printf 'usage: %s <vmlinux-btf>\n' "$0" >&2
	exit 2
fi
btf=$1

grep -aq 'signature_size' "$btf" || {
	echo "$btf lacks bpf_attr.signature_size; needs a signed-BPF capable bpf-next kernel" >&2
	exit 1
}

sh .github/scripts/debian-deps.sh
uname -m
cc --version | head -n 1

export BPF_VMLINUX_BTF="$btf"
make -j"$(nproc)"
make shirudo-build
make quote-check
make -C testing unit
sh .github/scripts/check-operator-linkage.sh shirudo \
	tools/shirudo-build/shirudo-build
sh .github/scripts/check-static-target.sh \
	tools/quote-check/shirudo-quote-check
