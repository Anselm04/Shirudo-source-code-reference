#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/install-static-libcrypto-deps.sh -- install the static
# archives shirudo-quote-check links beside libcrypto.a. Which ones depends
# on how the libcrypto in use was built, so the list is read from
# "pkg-config --static --libs libcrypto" and not kept here: a
# distribution's OpenSSL may name zlib, zstd and a jitter entropy source,
# one built from source names none of them.
#
#   .github/scripts/install-static-libcrypto-deps.sh
#
# Run as root on Debian or Ubuntu, after libssl-dev and pkg-config are
# installed and with the PKG_CONFIG_PATH the build will use.

set -eu

libs=$(pkg-config --static --libs libcrypto)

# The first of the named packages the distribution has.
first_available() {
	for pkg; do
		if apt-cache show "$pkg" >/dev/null 2>&1; then
			printf '%s\n' "$pkg"
			return 0
		fi
	done
	printf 'install-static-libcrypto-deps: none of %s is available\n' "$*" >&2
	return 1
}

pkgs=libc6-dev
for lib in $libs; do
	case $lib in
	-lz)
		pkgs="$pkgs zlib1g-dev"
		;;
	-lzstd)
		pkgs="$pkgs libzstd-dev"
		;;
	-ljitterentropy|-l:libjitterentropy.a)
		pkgs="$pkgs $(first_available libjitterentropy3-dev libjitterentropy-dev)"
		;;
	-lcrypto|-ldl|-lpthread|-pthread|-latomic|-L*)
		;;
	*)
		printf 'install-static-libcrypto-deps: no package known for %s\n' "$lib" >&2
		exit 1
		;;
	esac
done

# shellcheck disable=SC2086
apt-get install -y --no-install-recommends $pkgs
