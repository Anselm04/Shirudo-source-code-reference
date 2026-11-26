// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The history root of an upatch tree, apart from the register code of
 * chain.c, so that the publisher computes a segment's base without the TPM.
 */

#include <string.h>

#include "chain.h"
#include "crypto.h"

int chain_history_step(const __u8 prev[32], const __u8 operation_digest[32],
		       __u8 out[32])
{
	static const char tag[] = "shirudo-tree-history";
	__u8 buf[sizeof(tag) + 64];
	int ret;

	memcpy(buf, tag, sizeof(tag));
	memcpy(buf + sizeof(tag), prev, 32);
	memcpy(buf + sizeof(tag) + 32, operation_digest, 32);
	ret = sha256_buffer(buf, sizeof(buf), out);
	if (ret)
		memset(out, 0, 32);
	return ret;
}
