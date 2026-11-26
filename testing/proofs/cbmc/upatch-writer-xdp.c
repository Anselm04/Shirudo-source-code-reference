// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The attach metadata proof for XDP sections, a first digit and any TAIL
 * bytes behind it, one program or two: the writer takes a mask only of the
 * device classes the reader knows, and no class for two programs.
 */

#define XDP_OBJECTS
#include "upatch-writer-prog-specs.c"
