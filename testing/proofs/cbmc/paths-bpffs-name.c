// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * upatch_bpffs_name() and upatch_name_from_bpffs() of util/paths.h, which
 * map an upatch name to its pin directory and back, on every string of up
 * to LEN_MAX bytes: a name without the ~ no valid name has maps to one
 * without a dot, which bpffs refuses, and back to itself, and a pin name
 * without a dot that decodes is the encoding of what it decodes to.
 */

#include <stdbool.h>

#include "proof.h"
#include "../../../util/paths.h"

#define LEN_MAX	4

static char *any_string(size_t len)
{
	char *s = any_bytes(len + 1);

	__CPROVER_assume(!s[len] && strnlen(s, len) == len);
	return s;
}

static bool holds(const char *s, size_t len, char c)
{
	return memchr(s, c, len);
}

static void name_round_trips(void)
{
	char bpffs[2 * LEN_MAX + 1], back[LEN_MAX + 1];
	size_t len;
	char *name;

	__CPROVER_assume(len <= LEN_MAX);
	name = any_string(len);
	__CPROVER_assume(!holds(name, len, '~'));
	__CPROVER_assert(!upatch_bpffs_name(bpffs, sizeof(bpffs), name),
			 "every name fits twice its length");
	__CPROVER_assert(!holds(bpffs, strnlen(bpffs, sizeof(bpffs)), '.'),
			 "no dot for bpffs");
	__CPROVER_assert(!upatch_name_from_bpffs(back, sizeof(back), bpffs) &&
			 strnlen(back, sizeof(back)) == len &&
			 !memcmp(back, name, len),
			 "and back to the name");
}

static void pin_name_is_an_encoding(void)
{
	char name[2 * LEN_MAX + 1], again[4 * LEN_MAX + 1];
	size_t len;
	char *pin;

	__CPROVER_assume(len <= 2 * LEN_MAX);
	pin = any_string(len);
	__CPROVER_assume(!holds(pin, len, '.'));
	if (upatch_name_from_bpffs(name, sizeof(name), pin))
		return;
	__CPROVER_assert(!upatch_bpffs_name(again, sizeof(again), name) &&
			 strnlen(again, sizeof(again)) == len &&
			 !memcmp(again, pin, len),
			 "the encoding of the name it decodes to");
}

void harness(void)
{
	name_round_trips();
	pin_name_is_an_encoding();
}
