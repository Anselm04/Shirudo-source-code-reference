#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7111 -- a target takes a tree publication only under the manifest bpm
# tree append writes for its two layers: the same signed layers served
# under a manifest of the registry's own making are refused before the
# node records anything, and the publisher's form is taken again after.
# Runs after t7109, on the publication it left configured.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
WORK=$(mktemp -d)
# The fixtures are read-only; the registry serves a copy of them.
REGISTRY="$WORK/tree-oci"
MANIFEST="$REGISTRY/shirudo/upatch-tree/manifests/unmatched"

[ -s "$FIXTURES/tree-oci/shirudo/upatch-tree/manifests/unmatched" ] ||
	test_skip_all "missing tree fixture: unmatched"
[ -s "$TREE_STATE_FILE" ] || test_skip_all "no tree state to keep"
cleanup()
{
	tree_registry_stop
	rm -rf "$WORK"
}
trap cleanup EXIT
cp -R "$FIXTURES/tree-oci" "$REGISTRY"
cp "$MANIFEST" "$WORK/manifest"
tree_registry_start "$REGISTRY" "$WORK"
cp "$TREE_STATE_FILE" "$WORK/state"

test_expect_success 'the publication syncs under the publisher manifest' '
	tree_sync "$WORK/before.json" &&
	cmp -s "$TREE_STATE_FILE" "$WORK/state"
'
test_expect_success 'the same layers under a re-wrapped manifest are refused' '
	python3 -c "
import json, sys
manifest = json.load(open(sys.argv[1]))
open(sys.argv[1], \"w\").write(json.dumps(manifest, indent=1))
" "$MANIFEST" &&
	! tree_sync "$WORK/wrapped.json" &&
	cmp -s "$TREE_STATE_FILE" "$WORK/state"
'
test_expect_success 'and the publisher manifest is taken again after it' '
	cp "$WORK/manifest" "$MANIFEST" &&
	tree_sync "$WORK/after.json" &&
	cmp -s "$TREE_STATE_FILE" "$WORK/state"
'
test_done
