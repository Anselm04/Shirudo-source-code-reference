#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause

set -eu

export LC_ALL=C
readelf=${READELF:-readelf}

# The libraries AGENTS.md admits, by soname without its version.
allowed='libc libcrypto libssl libcurl libtss2-esys libtss2-tctildr libelf libz libluajit-5.1'

if [ "$#" -eq 0 ]; then
	printf 'usage: %s <operator-binary>...\n' "$0" >&2
	exit 2
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

bad=0
for bin; do
	"$readelf" -lW "$bin" >"$work/programs"
	"$readelf" -dW "$bin" >"$work/dynamic"
	interp=$(sed -n 's/.*\[Requesting program interpreter: \(.*\)\]$/\1/p' \
		"$work/programs")
	sed -n 's/.*(NEEDED).*Shared library: \[\(.*\)\]$/\1/p' \
		"$work/dynamic" >"$work/needed"
	while read -r lib; do
		if [ -n "$interp" ] && [ "$lib" = "${interp##*/}" ]; then
			continue
		fi
		case " $allowed " in
		*" ${lib%%.so*} "*)
			continue
			;;
		esac
		printf 'shirudo: %s links %s, which is not a library an operator binary may link\n' \
			"$bin" "$lib" >&2
		bad=1
	done <"$work/needed"
done

exit "$bad"
