// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * How tree_event_replay() of util/bpm_tree_state.c cuts the tree eventlog
 * into lines, on every eventlog of LEN bytes: each whole line is read
 * once and in order, an empty line is skipped, nothing of a last line
 * without its newline is read, and a log with a NUL is refused unread.
 * The lines hold records that replay, but for one line at most.
 */

#define TREE_REPLAY_LINES	1
#include "bpm-tree-state-replay.c"
