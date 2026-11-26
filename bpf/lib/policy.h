/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The task and socket policy maps that policy-label upatches share.
 */

#ifndef SHIRUDO_BPF_POLICY_H
#define SHIRUDO_BPF_POLICY_H

#include "xattr.h"

struct task_policy {
	__u64	active;
	__u64	candidate;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_policy);
} shirudo_task_policy SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_CLONE);
	__type(key, int);
	__type(value, __u64);
} shirudo_sock_policy SEC(".maps");

#endif /* SHIRUDO_BPF_POLICY_H */
