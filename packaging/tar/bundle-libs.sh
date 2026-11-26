#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -eu

if [ "$#" -ne 2 ]; then
	printf '%s\n' "usage: $0 <binary> <private-libdir>" >&2
	exit 2
fi

binary=$1
libdir=$2

if [ ! -x "$binary" ]; then
	printf '%s\n' "shirudo bundle-libs: not executable: $binary" >&2
	exit 1
fi

if ! command -v ldd >/dev/null 2>&1; then
	printf '%s\n' "shirudo bundle-libs: ldd not found" >&2
	exit 1
fi

tmp=${TMPDIR:-/tmp}/shirudo-bundle-libs.$$
trap 'rm -f "$tmp"' EXIT HUP INT TERM

ldd "$binary" | awk '
	/=> \// { print $3; next }
	/^\// { print $1; next }
' | sort -u > "$tmp"

install -d "$libdir"

while IFS= read -r lib; do
	[ -n "$lib" ] || continue
	base=${lib##*/}

	case "$base" in
		ld-linux*.so*|ld-musl*.so*|libc.so.*|libpthread.so.*|\
		libdl.so.*|libm.so.*|librt.so.*|libresolv.so.*|\
		libutil.so.*|libnsl.so.*|libanl.so.*)
			continue
			;;
	esac

	if [ ! -f "$lib" ]; then
		printf '%s\n' "shirudo bundle-libs: skipping missing $lib" >&2
		continue
	fi

	printf '  BUNDLE  %s\n' "$base"
	install -m 0644 "$lib" "$libdir/$base"
done < "$tmp"
