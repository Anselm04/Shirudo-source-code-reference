#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/install-clang.sh -- install clang and LLVM 23, the release
# CI builds and tests with, and make clang, llvm-strip, llvm-objcopy and
# llvm-symbolizer name it, as shirudo-build runs /usr/bin/clang. Debian
# unstable, as the LVH guests run it, and Fedora 45 ship it. Debian testing
# takes it from unstable, at a priority that leaves every other package to
# testing, and Ubuntu from apt.llvm.org, whose signing key must have the
# fingerprint below. Further packages from the same sources, a sanitizer
# runtime for instance, go on the command line.
#
#   .github/scripts/install-clang.sh [<package>...]
#
# Runs as root in a runner, container or LVH guest that is discarded
# afterwards: it adds package sources and replaces /usr/bin/clang.

set -eu

LLVM=23
LLVM_APT_KEY=6084F3CF814B57C1CF12EFD515CF4D18AF4F7421

. /etc/os-release

case $ID in
fedora)
	dnf -q install -y clang llvm "$@"
	;;
debian | ubuntu)
	export DEBIAN_FRONTEND=noninteractive
	apt-get update
	release=
	# Debian testing and unstable share one codename, so ask apt.
	if ! apt-cache policy "clang-$LLVM" | grep -q 'Candidate: [0-9]'; then
		if [ "$ID" = debian ]; then
			echo 'deb http://deb.debian.org/debian unstable main' \
				>/etc/apt/sources.list.d/unstable.list
			printf 'Package: *\nPin: release a=unstable\nPin-Priority: 100\n' \
				>/etc/apt/preferences.d/unstable
			release=unstable
		else
			apt-get install -y --no-install-recommends ca-certificates \
				curl gpg
			key=$(mktemp)
			curl -fsSL --retry 3 -o "$key" \
				https://apt.llvm.org/llvm-snapshot.gpg.key
			fpr=$(gpg --show-keys --with-colons "$key" |
				awk -F: '/^fpr/ { print $10; exit }')
			if [ "$fpr" != "$LLVM_APT_KEY" ]; then
				printf 'install-clang: apt.llvm.org key %s is not %s\n' \
					"$fpr" "$LLVM_APT_KEY" >&2
				exit 1
			fi
			gpg --dearmor --yes -o /usr/share/keyrings/apt-llvm.gpg "$key"
			rm -f "$key"
			echo "deb [signed-by=/usr/share/keyrings/apt-llvm.gpg] http://apt.llvm.org/$VERSION_CODENAME/ llvm-toolchain-$VERSION_CODENAME-$LLVM main" \
				>/etc/apt/sources.list.d/apt-llvm.list
		fi
		apt-get update
	fi
	set -- "clang-$LLVM" "llvm-$LLVM" "$@"
	if [ -n "$release" ]; then
		set -- -t "$release" "$@"
	fi
	apt-get install -y --no-install-recommends "$@"
	for tool in clang llvm-strip llvm-objcopy llvm-symbolizer; do
		ln -sf "/usr/lib/llvm-$LLVM/bin/$tool" "/usr/bin/$tool"
	done
	;;
*)
	printf 'install-clang: %s is not supported\n' "$ID" >&2
	exit 1
	;;
esac

version=$(clang -dumpversion)
case $version in
"$LLVM".*) ;;
*)
	printf 'install-clang: clang is %s, not %s\n' "$version" "$LLVM" >&2
	exit 1
	;;
esac
printf 'install-clang: clang %s\n' "$version"
