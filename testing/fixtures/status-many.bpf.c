// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

/* A raw tracepoint takes any number of programs; a trampoline does not. */
SEC("tp_btf/sched_process_free")
int BPF_PROG(shirudo_test_many)
{
	return 0;
}
