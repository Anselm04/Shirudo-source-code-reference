// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The attach metadata proof for uprobe sections, with any build ID and
 * offsets the ELF resolver finds, or none: the reader takes the target
 * block the writer appends, and reads back each record's path, build ID
 * and offsets for the program the record names.
 */

#define UPROBE_OBJECTS
#include "upatch-writer-prog-specs.c"
