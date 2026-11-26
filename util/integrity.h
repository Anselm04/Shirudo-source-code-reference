/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The integrity counters the LSM keeps, read back from their bpffs pin.
 */
#ifndef SHIRUDO_UTIL_INTEGRITY_H
#define SHIRUDO_UTIL_INTEGRITY_H

#include <shirudo/misc.h>

#include "bpf/lib/integrity.h"

struct integrity_counts {
	__u64		count[INTEGRITY_MAX];
	__u64		total;
};

const char *integrity_name(enum integrity_point point);
const char *integrity_meaning(enum integrity_point point);

/* As tamper_read(), for the integrity counters. */
int integrity_read(struct integrity_counts *out);

#endif /* SHIRUDO_UTIL_INTEGRITY_H */
