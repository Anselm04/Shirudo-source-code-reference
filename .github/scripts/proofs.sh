#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/proofs.sh -- install the pinned CBMC into build/cbmc or
# elan and Lean into ELAN_HOME, without root, or with sudo on Ubuntu the
# library headers the CBMC harnesses include, and list or run the CBMC
# proofs of shard <k> of <n>: every <n>th of proofs.list from the <k>th,
# but those ci-skip.list names, each alone under a memory and time cap.
#
#   .github/scripts/proofs.sh install-cbmc|install-headers|install-lean
#   .github/scripts/proofs.sh list|run <k> <n>

set -eu

# Diffblue's package of CBMC for Ubuntu 22.04 runs unpacked, without
# root, on later releases and other distributions; Ubuntu 26.04 packages
# CBMC 6.6.
CBMC_VERSION=5.95.1
CBMC_SHA256=bdfce55b828a45e19d685f7569e3569657ce80faa20c79a99f1791b5d5b852bc
ELAN_VERSION=4.2.4
ELAN_SHA256=42b94d4244e8353142c456ec0e4ca6528fd898a6c604d4059f494e706e431f63

# A runner has two CPUs and about 7 GB. A proof gets 6 GB, so that one
# past it fails as out of memory rather than taking the runner down with
# it, and the slowest proof CI runs takes 15 minutes on a fast host: a
# proof past either cap is one to reshape.
PROOF_MEMORY_KB=6000000
PROOF_MINUTES=60

cd "$(git rev-parse --show-toplevel)"
proofs=testing/proofs/cbmc

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

die() {
	printf 'proofs: %s\n' "$*" >&2
	exit 1
}

annotate() {
	[ -z "${GITHUB_ACTIONS:-}" ] || printf '::%s\n' "$*"
}

# Prints a directory to put on PATH and puts it on the job's.
add_path() {
	printf '%s\n' "$1"
	[ -z "${GITHUB_PATH:-}" ] || printf '%s\n' "$1" >>"$GITHUB_PATH"
}

fetch() {
	curl -fsSL --retry 3 -o "$1" "$2"
	printf '%s  %s\n' "$3" "$1" | sha256sum -c --quiet
}

# The pinned packages are built for x86_64 only.
check_arch() {
	[ "$(uname -m)" = x86_64 ] || die "the pinned packages are for x86_64"
}

install_cbmc() {
	check_arch
	dir=$PWD/build/cbmc
	if ! "$dir/usr/bin/cbmc" --version 2>/dev/null |
		grep -q "^$CBMC_VERSION "; then
		rm -rf "$dir"
		mkdir -p "$dir"
		url=https://github.com/diffblue/cbmc/releases/download
		deb=ubuntu-22.04-cbmc-$CBMC_VERSION-Linux.deb
		fetch "$work/cbmc.deb" "$url/cbmc-$CBMC_VERSION/$deb" \
			"$CBMC_SHA256"
		dpkg-deb -x "$work/cbmc.deb" "$dir"
	fi
	add_path "$dir/usr/bin"
}

# CBMC preprocesses a harness with the host's gcc, which takes the
# headers of the C library, OpenSSL, libcurl and zlib from the system.
# The runner image lacks libcurl's; the others are named too, so that the
# job does not rely on what the image happens to ship.
install_headers() {
	sudo=
	[ "$(id -u)" -eq 0 ] || sudo=sudo
	$sudo apt-get update
	$sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
		--no-install-recommends libc6-dev libcurl4-openssl-dev \
		libssl-dev linux-libc-dev zlib1g-dev
}

install_lean() {
	check_arch
	home=${ELAN_HOME:-$HOME/.elan}
	if ! "$home/bin/elan" --version 2>/dev/null |
		grep -q "^elan $ELAN_VERSION "; then
		url=https://github.com/leanprover/elan/releases/download
		fetch "$work/elan.tar.gz" \
			"$url/v$ELAN_VERSION/elan-x86_64-unknown-linux-gnu.tar.gz" \
			"$ELAN_SHA256"
		tar -xzf "$work/elan.tar.gz" -C "$work"
		ELAN_HOME=$home "$work/elan-init" -y --no-modify-path \
			--default-toolchain none
	fi
	ELAN_HOME=$home "$home/bin/elan" toolchain install \
		"$(cat testing/proofs/lean4/lean-toolchain)"
	add_path "$home/bin"
}

names() {
	grep -v '^[[:space:]]*\(#\|$\)' "$1" | awk '{ print $1 }'
}

shard() {
	case $1:$2 in
	*[!0-9:]* | :* | *:) die "list and run take <k> <n>, 1 <= k <= n" ;;
	esac
	if [ "$1" -lt 1 ] || [ "$1" -gt "$2" ]; then
		die "list and run take <k> <n>, 1 <= k <= n"
	fi
	names "$proofs/proofs.list" >"$work/all"
	names "$proofs/ci-skip.list" >"$work/skip"
	while read -r name; do
		grep -qxF "$name" "$work/all" ||
			die "ci-skip.list names $name, which proofs.list does not"
	done <"$work/skip"
	grep -vxF -f "$work/skip" "$work/all" |
		awk -v k="$1" -v n="$2" '(NR - 1) % n == k - 1'
}

# A proof stopped at its time cap leaves run.sh's CBMC logs behind; the
# newest is that of the length it was on.
prove() {
	name=$1
	log=build/proofs/$name.log
	mkdir -p "$work/$name"
	status=0
	TMPDIR=$work/$name timeout "$((PROOF_MINUTES * 60))" \
		"$proofs/run.sh" -v "$name" </dev/null >"$log" 2>&1 || status=$?
	if [ "$status" -eq 0 ]; then
		grep '^ok' "$log"
		rm -f "$log"
		return 0
	fi
	why=$(sed -n 's/^FAILED  [^ ]* \((.*)\)$/failed \1/p' "$log" | head -n 1)
	[ -n "$why" ] || why=failed
	if [ "$status" -eq 124 ]; then
		why="no result in $PROOF_MINUTES minutes"
		# shellcheck disable=SC2012
		last=$(ls -t "$work/$name"/*/*.log 2>/dev/null | head -n 1)
		if [ -n "$last" ]; then
			len=${last##*/"$name".}
			len=${len%.log}
			[ "$len" = - ] || why="$why (-DLEN=$len)"
			cat "$last" >>"$log"
		fi
	elif grep -qi 'out of memory' "$log"; then
		why="out of memory at $((PROOF_MEMORY_KB / 1000000)) GB"
	fi
	printf 'FAILED  %s: %s\n' "$name" "$why"
	annotate "error title=CBMC proof $name::$why"
	grep -E 'FAILURE|ERROR|error:|no body for function|[Oo]ut of memory' \
		"$log" | head -n 20 | sed 's/^/        /' || :
	annotate "group::Output of $name"
	cat "$log"
	annotate "endgroup::"
	return 1
}

run() {
	shard "$1" "$2" >"$work/shard"
	printf 'proofs: shard %s of %s runs %s\n' "$1" "$2" \
		"$(paste -sd ' ' "$work/shard")"
	# dash and bash both take -v.
	# shellcheck disable=SC3045
	ulimit -v "$PROOF_MEMORY_KB"
	rm -rf build/proofs
	mkdir -p build/proofs
	ran=0
	failed=0
	while read -r name; do
		ran=$((ran + 1))
		prove "$name" || failed=$((failed + 1))
	done <"$work/shard"
	[ "$ran" -gt 0 ] || die "shard $1 of $2 has no proof"
	if [ "$failed" -gt 0 ]; then
		printf 'proofs: %d of %d failed\n' "$failed" "$ran" >&2
		exit 1
	fi
	printf 'proofs: %d hold\n' "$ran"
}

case ${1:-} in
install-cbmc) install_cbmc ;;
install-headers) install_headers ;;
install-lean) install_lean ;;
list) shard "${2:-}" "${3:-}" ;;
run) run "${2:-}" "${3:-}" ;;
*) die "usage: proofs.sh install-cbmc|install-headers|install-lean|list|run <k> <n>" ;;
esac
