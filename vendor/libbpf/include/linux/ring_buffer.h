/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * perf ring-buffer head/tail accessors for libbpf's perf_buffer.
 */

#ifndef SHIRUDO_VENDOR_LINUX_RING_BUFFER_H
#define SHIRUDO_VENDOR_LINUX_RING_BUFFER_H

#include <asm/barrier.h>
#include <linux/perf_event.h>

static inline __u64 ring_buffer_read_head(struct perf_event_mmap_page *base)
{
	return smp_load_acquire(&base->data_head);
}

static inline void ring_buffer_write_tail(struct perf_event_mmap_page *base,
					  __u64 tail)
{
	smp_store_release(&base->data_tail, tail);
}

#endif /* SHIRUDO_VENDOR_LINUX_RING_BUFFER_H */
