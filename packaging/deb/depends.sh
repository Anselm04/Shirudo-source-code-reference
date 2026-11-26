#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Emit a comma-separated Debian Depends list for the given ELF binaries,
# derived from their resolved shared-library paths via `dpkg -S`. Best
# effort and unversioned: for archive-quality versioned dependencies use
# dpkg-shlibdeps under a full debian/ build. Prints nothing if dpkg or
# ldd is unavailable, so the caller simply omits the Depends field.

set -eu

command -v dpkg >/dev/null 2>&1 || exit 0
command -v ldd >/dev/null 2>&1 || exit 0

libs=
for bin in "$@"; do
	[ -e "$bin" ] || continue
	# Absolute paths of the binary's resolved NEEDED libraries.
	libs="$libs
$(ldd "$bin" 2>/dev/null | sed -nE 's/.*=> (\/[^ ]+).*/\1/p')"
done

pkgs=
for lib in $libs; do
	[ -n "$lib" ] || continue
	real=$(readlink -f "$lib" 2>/dev/null || echo "$lib")
	pkg=$(dpkg -S "$real" 2>/dev/null | head -n1 | cut -d: -f1) || true
	[ -n "${pkg:-}" ] && pkgs="$pkgs $pkg"
done

# Unique, sorted, comma-joined ("pkg1, pkg2, ...").
[ -n "$pkgs" ] || exit 0
printf '%s\n' $pkgs | sort -u | paste -sd, - | sed 's/,/, /g'
