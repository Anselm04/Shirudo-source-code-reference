// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe.multi/vfs_read,shirudo_no_such_function")
int km_missing(struct pt_regs *ctx)
{
	return 0;
}
