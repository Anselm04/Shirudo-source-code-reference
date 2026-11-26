#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -eu

archive_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
root_dir="$archive_dir/root"
destdir=${DESTDIR:-/}

if [ ! -d "$root_dir" ]; then
	printf '%s\n' "shirudo installer: missing staged root: $root_dir" >&2
	exit 1
fi

if [ "$destdir" = "/" ] && [ "$(id -u)" != "0" ]; then
	printf '%s\n' "shirudo installer: run as root, or set DESTDIR=/path" >&2
	exit 1
fi

install -d "$destdir"
cp -a "$root_dir"/. "$destdir"/

if [ "$destdir" = "/" ] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
fi

printf 'shirudo installer: installed into %s\n' "$destdir"
