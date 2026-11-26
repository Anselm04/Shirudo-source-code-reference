// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "Dual BSD/GPL";

enum {
	HIT_ENTRY,
	HIT_RETURN,
	NR_HITS,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_HITS);
	__type(key, __u32);
	__type(value, __u64);
} hits SEC(".maps");

static __always_inline void count_hit(__u32 slot)
{
	__u64 *value = bpf_map_lookup_elem(&hits, &slot);

	if (value)
		__sync_fetch_and_add(value, 1);
}

SEC("kprobe.multi/vfs_write,vfs_read")
int km_entry(struct pt_regs *ctx)
{
	count_hit(HIT_ENTRY);
	return 0;
}

SEC("kretprobe.multi/vfs_read,vfs_write")
int km_return(struct pt_regs *ctx)
{
	count_hit(HIT_RETURN);
	return 0;
}
