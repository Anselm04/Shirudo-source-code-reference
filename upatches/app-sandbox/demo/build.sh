#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# usage: build.sh <archive>
#
# Builds the image of the Dockerfile beside this script and writes its
# file system to <archive>, a tar, for apache.sh to run Apache from on a
# target, which has no Docker. Needs Docker and, the first time, the
# network; no root.

set -eu

[ $# -eq 1 ] || { echo "usage: $0 <archive>" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
image=shirudo-app-sandbox-demo

docker build -q -t "$image" "$here" >/dev/null
container=$(docker create "$image")
trap 'docker rm "$container" >/dev/null' EXIT
# The target binds its own /dev there.
docker export "$container" >"$1"
echo "$image -> $1"
