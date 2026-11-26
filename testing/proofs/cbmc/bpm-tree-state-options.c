// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The table tree_selector_matches() of util/bpm_tree_state.c looks a kernel
 * option up in: selector_hash_find() finds a key at the first pair that has
 * it and no key that none has, so an option has one value, as kconfig of
 * testing/proofs/lean4/Shirudo/TreeOverlap.lean gives it.
 */

#define TREE_STATE_OPTIONS	1
/* The stubs of the node there take a LEN, which no option reads. */
#define LEN			0
#include "bpm-tree-state-match.c"
