#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/proofs/cbmc/run.sh -- check with CBMC that shirudo's parsers keep the
# properties the harnesses in this directory state, for every input within
# the bounds each harness names, and fail when one does not hold. Each
# harness defines harness() and includes the source it proves; proofs.list
# gives its CBMC options, and LEN=<a>-<b>,<c> there runs it once for each
# length the list of lengths and ranges names, as CBMC handles a fixed
# length far faster than one it has to keep symbolic. -v prints the whole
# CBMC output and the trace of a failed check. -c takes what git diff
# takes, a range of commits or one to compare the working tree with, and
# runs only the proofs whose harness reads a file changed there, as the
# compiler lists what each harness includes; a change to this script or
# to proofs.list runs them all.
#
#   testing/proofs/cbmc/run.sh [-v] [-c <rev-range>] [<proof>...]

set -eu

verbose=
range=
while getopts vc: opt; do
	case $opt in
	v) verbose=--trace ;;
	c) range=$OPTARG ;;
	*) exit 2 ;;
	esac
done
shift $((OPTIND - 1))

cd "$(dirname "$0")"
root=$(cd ../../.. && pwd)
command -v cbmc >/dev/null 2>&1 || {
	printf 'proofs: cbmc not found; install cbmc\n' >&2
	exit 2
}

# The build's include paths, so that a harness reads the headers the code
# is built with: the libbpf and UAPI headers of vendor/libbpf, not the
# host's.
includes='-I ../../.. -I ../../../include -I ../../../util
	-I ../../../vendor/libbpf -I ../../../vendor/libbpf/include/uapi'

# --unsigned-char as the build's -funsigned-char.
checks='--unsigned-char --bounds-check --pointer-check
	--pointer-primitive-check --div-by-zero-check --signed-overflow-check
	--undefined-shift-check --pointer-overflow-check --conversion-check
	--unwinding-assertions'

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if [ -n "$range" ]; then
	git diff --name-only "$range" >"$work/changed"
	if grep -qxE 'testing/proofs/cbmc/(run\.sh|proofs\.list)' "$work/changed"; then
		range=
	fi
fi

# Whether a harness, built with the -D options and the first length of
# its line, reads a changed file. One the compiler cannot list counts as
# changed.
touched() {
	name=$1
	shift
	flags=
	for o in "$@"; do
		case $o in
		-D*) flags="$flags $o" ;;
		LEN=*)
			o=${o#LEN=}
			flags="$flags -DLEN=${o%%[-,]*}"
			;;
		esac
	done
	# shellcheck disable=SC2086
	"${CC:-cc}" -MM $includes -D_GNU_SOURCE $flags "$name.c" \
		>"$work/deps" 2>/dev/null || return 0
	sed 's/\\$//' "$work/deps" | tr -s ' ' '\n' | grep -v ':$' | grep . |
		xargs realpath --relative-to="$root" |
		grep -qxF -f "$work/changed"
}

wanted() {
	name=$1
	shift 2
	[ $# -eq 0 ] && return 0
	for p in "$@"; do
		[ "$p" = "$name" ] && return 0
	done
	return 1
}

# One CBMC run; a function CBMC has no body for returns anything, which
# proves nothing about the code that calls it.
prove() {
	log=$1
	shift
	# shellcheck disable=SC2086
	cbmc --function harness $includes -D_GNU_SOURCE $checks "$@" \
		$verbose >"$log" 2>&1 &&
		! grep -q 'no body for function' "$log"
}

failed=0
ran=0
grep -v '^[[:space:]]*\(#\|$\)' proofs.list >"$work/list"
while read -r name opts; do
	wanted "$name" -- "$@" || continue
	# shellcheck disable=SC2086
	[ -z "$range" ] || touched "$name" $opts || continue
	ran=$((ran + 1))
	lens=-
	rest=
	for o in $opts; do
		case $o in
		LEN=*) lens=${o#LEN=} ;;
		*) rest="$rest $o" ;;
		esac
	done
	[ "$lens" = - ] ||
		lens=$(printf '%s\n' "$lens" | tr ',' '\n' |
			while IFS=- read -r from to; do
				seq "$from" "${to:-$from}"
			done)
	start=$(date +%s)
	checked=0
	bad=
	for len in $lens; do
		log=$work/$name.$len.log
		define=
		[ "$len" = - ] || define="-DLEN=$len"
		# shellcheck disable=SC2086
		if prove "$log" $define $rest "$name.c"; then
			n=$(grep -o 'of [0-9]* failed' "$log" | tail -1 | tr -dc '0-9')
			checked=$((checked + ${n:-0}))
			continue
		fi
		bad=${define:-all}
		break
	done
	if [ -z "$bad" ]; then
		printf 'ok      %-28s %6d checks, %ss\n' "$name" "$checked" \
			"$(($(date +%s) - start))"
		continue
	fi
	failed=$((failed + 1))
	printf 'FAILED  %s (%s)\n' "$name" "$bad"
	if [ -n "$verbose" ]; then
		cat "$log"
	else
		grep -E 'FAILURE|ERROR|error:|no body for function|out of memory' \
			"$log" | head -20 | sed 's/^/        /'
	fi
done <"$work/list"

[ "$ran" -gt 0 ] || {
	[ -z "$range" ] || {
		printf 'proofs: none reads a file changed in %s\n' "$range"
		exit 0
	}
	printf 'proofs: no proof named %s\n' "$*" >&2
	exit 2
}
if [ "$failed" -gt 0 ]; then
	printf 'proofs: %d of %d failed\n' "$failed" "$ran" >&2
	exit 1
fi
printf 'proofs: %d hold\n' "$ran"
