// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The upatch of the backward-walk end-to-end test that selects no label,
 * so that every node applies it. It attaches to a function every test
 * kernel has, so that it always loads.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/tcp_v4_connect")
int BPF_PROG(net_guard)
{
	return 0;
}
