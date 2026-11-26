/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The integrity counters: refusals of the ways to change or read the
 * running kernel, apart from the tamper counters of shirudo's own state.
 */
#ifndef SHIRUDO_INTEGRITY_H
#define SHIRUDO_INTEGRITY_H

/*
 * A counter's position is its identity in the keepalive and to every
 * backend that reads it: append only, never between two.
 */
enum integrity_point {
	INTEGRITY_MODULE_SIGNATURE,
	INTEGRITY_DEV_MEM,
	INTEGRITY_EFI_TEST,
	INTEGRITY_KEXEC,
	INTEGRITY_PCI_ACCESS,
	INTEGRITY_IOPORT,
	INTEGRITY_MSR,
	INTEGRITY_ACPI_TABLES,
	INTEGRITY_DEVICE_TREE,
	INTEGRITY_PCMCIA_CIS,
	INTEGRITY_TIOCSSERIAL,
	INTEGRITY_MODULE_PARAMETERS,
	INTEGRITY_MMIOTRACE,
	INTEGRITY_DEBUGFS,
	INTEGRITY_XMON_WR,
	INTEGRITY_BPF_WRITE_USER,
	INTEGRITY_DBG_WRITE_KERNEL,
	INTEGRITY_RTAS_ERROR_INJECTION,
	INTEGRITY_XEN_USER_ACTIONS,
	INTEGRITY_KCORE,
	INTEGRITY_HIBERNATE_LOCATION,
	INTEGRITY_OTHER,
	INTEGRITY_MAX
};

#ifdef __BPF__
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, INTEGRITY_MAX);
	__type(key, __u32);
	__type(value, __u64);
} shirudo_integrity SEC(".maps");

static __always_inline int shirudo_integrity_deny(enum integrity_point point,
						  int err)
{
	__u32 key = point;
	__u64 *count;

	count = bpf_map_lookup_elem(&shirudo_integrity, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
	return err;
}
#endif /* __BPF__ */
#endif /* SHIRUDO_INTEGRITY_H */
