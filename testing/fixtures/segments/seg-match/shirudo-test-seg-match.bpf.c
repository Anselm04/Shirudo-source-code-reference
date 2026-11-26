// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * An operation of the segmented tree t7108 walks. It attaches to a function
 * every test kernel has, so that it always loads.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/do_nanosleep")
int BPF_PROG(shirudo_test_seg_match)
{
	return 0;
}
