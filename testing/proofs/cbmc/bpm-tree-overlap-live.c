// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * tree_add_live() of util/bpm_tree_overlap.c is addLive of
 * testing/proofs/lean4/Shirudo/TreeOverlap.lean on every publication of up
 * to OPS_MAX operations: an add is live until a later delete of its upatch
 * covers its selector.
 */

#define TREE_OVERLAP_LIVE	1
#define OPS_MAX			3
#include "bpm-tree-overlap-model.c"
