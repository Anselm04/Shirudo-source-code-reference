#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/check-coccinelle.sh -- run the semantic patches in
# testing/coccinelle over the C the project writes and fail on any match:
# each one describes a pattern the tree is kept free of, and reports
# file:line: message where it finds the pattern again.
#
#   .github/scripts/check-coccinelle.sh [<rule>...]
#
# The rules that can rewrite what they find do so with -D patch:
#
#   spatch -D patch --sp-file testing/coccinelle/<rule>.cocci \
#          --in-place --include-headers <file>...
#
# Runs from anywhere inside the checkout and needs spatch, Coccinelle
# built with Python, as Debian and Ubuntu ship it.

set -eu

cd "$(git rev-parse --show-toplevel)"
command -v spatch >/dev/null 2>&1 || {
	printf 'check-coccinelle: spatch not found; install coccinelle\n' >&2
	exit 2
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The C the project writes, as check-style.sh takes it: not the vendored
# libbpf, not the BTF dumps and not the generated headers.
git ls-files -- '*.c' '*.h' ':(exclude)vendor/' ':(exclude)*vmlinux.h' \
	':(exclude)*_generated.h' >"$work/files"

if [ $# -eq 0 ]; then
	set -- testing/coccinelle/*.cocci
fi

jobs=${COCCI_JOBS:-$(nproc 2>/dev/null || echo 1)}
bad=0
for rule in "$@"; do
	case $rule in
	*.cocci) ;;
	*) rule=testing/coccinelle/$rule.cocci ;;
	esac
	name=$(basename "$rule" .cocci)
	# Without the headers a file includes the run is fast, but the types
	# they declare are unknown. A rule that needs them names the include
	# options on a #spatch line, which --no-includes would override.
	includes=--no-includes
	if grep -q '^#spatch' "$rule"; then
		includes=
	fi
	# Each file on its own, so that one Coccinelle cannot parse costs only
	# that file, and in parallel. A rule with a time limit takes a file
	# per run, as spatch gives up on all a run was given.
	per=16
	if grep -q '^#spatch.*--timeout' "$rule"; then
		per=1
	fi
	xargs -P "$jobs" -n "$per" spatch -D report --very-quiet $includes \
		--include-headers --sp-file "$rule" <"$work/files" \
		>"$work/$name.out" 2>"$work/$name.err" ||
		if grep -v -e '^timeout (we abort): ' \
		    -e '^Fatal error: exception .*Timeout$' \
		    "$work/$name.err" | grep -q .; then
			cat "$work/$name.err" >&2
			printf 'check-coccinelle: %s: spatch failed\n' "$name" >&2
			bad=$((bad + 1))
			continue
		fi
	sed -n 's/^timeout (we abort): //p' "$work/$name.err" |
		while IFS= read -r file; do
			printf 'check-coccinelle: %s: gave up on %s at its time limit\n' \
				"$name" "$file" >&2
		done
	sort -u "$work/$name.out" >"$work/$name.sorted"
	[ -s "$work/$name.sorted" ] || continue
	bad=$((bad + 1))
	while IFS= read -r line; do
		printf '%s: %s\n' "$name" "$line" >&2
		if [ -n "${GITHUB_ACTIONS:-}" ]; then
			f=${line%%:*}
			rest=${line#*:}
			l=${rest%%:*}
			printf '::error file=%s,line=%s::%s: %s\n' "$f" "$l" \
				"$name" "${line#*: }"
		fi
	done <"$work/$name.sorted"
done

if [ "$bad" -gt 0 ]; then
	printf 'check-coccinelle: %d of %d rules matched\n' "$bad" "$#" >&2
	exit 1
fi
printf 'check-coccinelle: %d rules, no match\n' "$#"
