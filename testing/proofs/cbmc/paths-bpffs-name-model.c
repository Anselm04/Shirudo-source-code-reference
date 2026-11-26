// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * upatch_bpffs_name() and upatch_name_from_bpffs() of util/paths.h against
 * the model testing/proofs/lean4/Shirudo/PinName.lean proves a bijection
 * for names of every length: on every string of up to LEN_MAX bytes and
 * every buffer of up to SZ_MAX bytes they return what bpffsName and
 * nameFromBpffs return, and write the same string.
 */

#include <errno.h>
#include <stdbool.h>

#include "proof.h"
#include "../../../util/paths.h"

#define LEN_MAX	8
#define SZ_MAX	(2 * LEN_MAX + 2)

static char *any_string(size_t len)
{
	char *s = any_bytes(len + 1);

	__CPROVER_assume(!s[len] && strnlen(s, len) == len);
	return s;
}

/* bpffsName: the length check, then encode, each dot as ~d. */
static int model_bpffs_name(const char *name, size_t len, size_t out_sz,
			    char *out, size_t *n)
{
	size_t i, j = 0;

	if (!out_sz)
		return -EINVAL;
	if (len * 2 + 1 > out_sz)
		return -ENAMETOOLONG;
	for (i = 0; i < len; i++) {
		if (name[i] == '.') {
			out[j++] = '~';
			out[j++] = 'd';
		} else {
			out[j++] = name[i];
		}
	}
	*n = j;
	return 0;
}

/* nameFromBpffs: fromLoop from j = 0, one pattern of the model a turn. */
static int model_name_from_bpffs(const char *p, size_t len, size_t out_sz,
				 char *out, size_t *n)
{
	size_t i = 0, j = 0;

	if (!out_sz)
		return -EINVAL;
	while (i < len) {
		char c = p[i];

		if (c == '~') {
			if (i + 1 == len || p[i + 1] != 'd')
				return -EINVAL;
			if (j + 1 >= out_sz)
				return -ENAMETOOLONG;
			out[j++] = '.';
			i += 2;
			continue;
		}
		if (j + 1 >= out_sz)
			return -ENAMETOOLONG;
		out[j++] = c;
		i++;
	}
	*n = j;
	return 0;
}

static void encode_is_model(void)
{
	char out[SZ_MAX], want[SZ_MAX];
	size_t len, sz, n;
	int ret, model;
	char *name;

	__CPROVER_assume(len <= LEN_MAX && sz <= SZ_MAX);
	name = any_string(len);
	ret = upatch_bpffs_name(out, sz, name);
	model = model_bpffs_name(name, len, sz, want, &n);
	__CPROVER_assert(ret == model, "bpffsName's result");
	if (ret)
		return;
	__CPROVER_assert(n < sz && !out[n] && !memcmp(out, want, n),
			 "and its encoding");
}

static void decode_is_model(void)
{
	char out[SZ_MAX], want[SZ_MAX];
	size_t len, sz, n;
	int ret, model;
	char *pin;

	__CPROVER_assume(len <= LEN_MAX && sz <= SZ_MAX);
	pin = any_string(len);
	ret = upatch_name_from_bpffs(out, sz, pin);
	model = model_name_from_bpffs(pin, len, sz, want, &n);
	__CPROVER_assert(ret == model, "nameFromBpffs's result");
	if (ret)
		return;
	__CPROVER_assert(n < sz && !out[n] && !memcmp(out, want, n),
			 "and its decoding");
}

void harness(void)
{
	encode_is_model();
	decode_is_model();
}
