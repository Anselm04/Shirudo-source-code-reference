#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7105 -- an add whose upatch is already loaded with its payload, as a
# sync stopped between the load and its tree record leaves it, counts as
# installed, while a direct load of it is still refused.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
REGISTRY="$FIXTURES/tree-oci"
TREE_REPO="$REGISTRY/shirudo/upatch-tree"
MATCH=$FIXTURES/shirudo-test-tree-match.upatch
MATCH_PIN=/run/shirudo/bpffs/upatches/shirudo-test-tree-match/link
WORK=$(mktemp -d)

for fixture in \
	"$TREE_REPO/manifests/reloaded" \
	"$MATCH" \
	"$FIXTURES/shirudo-test-tree-match.unload.upatch" \
	"$FIXTURES/cert.der" \
	"./helper/test-oci-registry.py"
do
	[ -s "$fixture" ] || test_skip_all "missing tree fixture: $fixture"
done

[ "$(tree_state_field tree_id)" = shirudo-test-tree ] &&
	[ "$(tree_state_field last_seq)" = 6 ] && [ ! -e "$MATCH_PIN" ] ||
	test_skip_all "tree state is not where t7104 leaves it"

cleanup()
{
	tree_registry_stop
	if [ -e "$MATCH_PIN" ]; then
		"$SHIRUDO_BIN" upatch unload \
			"$FIXTURES/shirudo-test-tree-match.unload.upatch" \
			--no-precheck >/dev/null 2>&1 || true
	fi
	tree_cleanup_config
	rm -rf "$WORK"
}
trap cleanup EXIT

tree_configure reloaded
tree_registry_start "$REGISTRY" "$WORK"

test_expect_success 'the upatch of the next add is loaded by hand first' '
	"$SHIRUDO_BIN" upatch load "$MATCH" --no-precheck >/dev/null 2>&1 &&
	[ -e "$MATCH_PIN" ]
'

test_expect_success 'a direct load of the same artifact is still refused' '
	! "$SHIRUDO_BIN" upatch load "$MATCH" --no-precheck \
		>/dev/null 2>"$WORK/again.err" &&
	grep -q "is already loaded; unload it" "$WORK/again.err"
'

test_expect_success 'the sync counts the loaded payload as installed' '
	tree_sync "$WORK/applied.json" &&
	[ "$(report_field applied <"$WORK/applied.json")" = 1 ] &&
	[ "$(report_field last_seq <"$WORK/applied.json")" = 7 ] &&
	[ -e "$MATCH_PIN" ]
'

test_done
