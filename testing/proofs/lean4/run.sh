#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/proofs/lean4/run.sh -- check the Lean 4 proofs of the models of
# shirudo's algorithms in this directory. A proof left unfinished with
# sorry, or any other warning, fails the build; Lean's kernel and nanoda,
# a second kernel, then check every proof again.
#
#   testing/proofs/lean4/run.sh

set -eu

cd "$(dirname "$0")"
command -v lake >/dev/null 2>&1 || {
	printf 'proofs: lake not found; install elan and run elan toolchain install %s\n' \
		"$(cat lean-toolchain)" >&2
	exit 2
}
lake build

# The tactics and a restored build cache are not trusted: both checkers
# read what the build wrote. nanoda, written apart from Lean, admits
# only the axioms nanoda.json permits, so a native_decide or an axiom of
# our own fails here. Each module is named, as an export of Shirudo
# alone would leave out one that Shirudo.lean does not import.
modules=$(find Shirudo -name '*.lean' | sed 's|\.lean$||; s|/|.|g' | sort)
bin=$(lean --print-prefix)/bin
export=$(mktemp)
trap 'rm -f "$export"' EXIT
lake env "$bin/leanchecker" Shirudo $modules
lake env "$bin/leanexport" Shirudo $modules >"$export"
"$bin/nanoda_bin" nanoda.json <"$export"
printf 'proofs: %s Lean 4 modules hold, checked again by two kernels\n' \
	"$(printf '%s\n' "$modules" | wc -l)"
