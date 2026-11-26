#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/check-unused.sh -- fail on a function the userspace C
# defines without static that nothing calls: the compiler reports an
# unused static function, never an extern one, so one whose last caller
# went stays behind. A function counts as used where its name appears in
# another C file, or in a header's macro or inline function; one the
# tests alone call is used.
#
#   .github/scripts/check-unused.sh
#
# Runs from anywhere inside the checkout and needs no build.

set -eu

cd "$(git rev-parse --show-toplevel)"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The C the project writes, as check-coccinelle.sh takes it.
git ls-files -- '*.c' '*.h' ':(exclude)vendor/' ':(exclude)*vmlinux.h' \
	':(exclude)*_generated.h' >"$work/files"
# Where an extern function is a definition to account for: not the BPF
# programs, whose entry points the loader finds by section, nor the
# proof harnesses, which stand in for functions of the code they prove.
grep '\.c$' "$work/files" | grep -v -e '^bpf/' -e '^upatches/' \
	-e '^testing/fixtures/' -e '^testing/proofs/' >"$work/defining"

# file:line:name of each extern definition: a line that opens with the
# name and its type, or with the name alone under its type, whose
# parameters close before a { in the first column. main, the entry
# points of libFuzzer and CBMC and the wrappers the linker's --wrap
# names are called from outside the C.
# shellcheck disable=SC2016 # awk program
xargs awk '
	FNR == 1 { pending = ""; prev = "" }
	/^[A-Za-z_]/ && !/^(static|typedef|struct [a-z_0-9]+ *\{|enum|union|extern)/ &&
	    !/;[ \t]*$/ && !/=.*\(/ && match($0, /[A-Za-z_][A-Za-z0-9_]*\(/) {
		name = substr($0, RSTART, RLENGTH - 1)
		head = substr($0, 1, RSTART - 1)
		if ((head != "" || prev !~ /(^|[^a-z_])static([^a-z_]|$)/) &&
		    prev !~ /^#define/)
			pending = name
		where = FNR
	}
	pending != "" && /\);[ \t]*$/ { pending = "" }
	/^\{/ && pending != "" {
		print FILENAME ":" where ":" pending
		pending = ""
	}
	{ prev = $0 }' <"$work/defining" |
	grep -v -E ':(main|harness|LLVMFuzzer[A-Za-z]*|__wrap_[A-Za-z0-9_]+)$' \
		>"$work/defined"

bad=0
while IFS=: read -r file line name; do
	xargs git grep -n -w -F -e "$name" -- <"$work/files" >"$work/uses" ||
		:
	# The definition is one mention in its file; a declaration of a
	# header opens its line, where a use in a macro or an inline
	# function does not.
	if awk -F: -v file="$file" -v name="$name" '
		$1 == file { own++; next }
		$1 ~ /\.h$/ && $3 !~ /^[ \t#]/ { next }
		{ found = 1 }
		END { exit !(found || own > 1) }' "$work/uses"; then
		continue
	fi
	bad=$((bad + 1))
	printf '%s:%s: %s() is defined, but nothing calls it\n' \
		"$file" "$line" "$name" >&2
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		printf '::error file=%s,line=%s::%s() is defined, but nothing calls it\n' \
			"$file" "$line" "$name"
	fi
done <"$work/defined"

n=$(wc -l <"$work/defined")
if [ "$bad" -gt 0 ]; then
	printf 'check-unused: %d of %d extern functions are not called\n' \
		"$bad" "$n" >&2
	exit 1
fi
printf 'check-unused: %d extern functions, each called\n' "$n"
