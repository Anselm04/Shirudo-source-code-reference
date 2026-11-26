// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The attach metadata proof for kprobe sections: a symbol of up to 127
 * bytes and an offset of up to 64 bits read back as written, kprobe multi
 * name lists read back sorted, beside a uprobe or another list, and the
 * sections the writer must refuse.
 */

#define KPROBE_OBJECTS
#include "upatch-writer-prog-specs.c"
