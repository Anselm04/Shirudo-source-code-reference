// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "hex.h"
#include "malloc.h"

void hex_encode(const __u8 *in, size_t n, char *out)
{
	static const char d[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < n; i++) {
		out[2 * i] = d[in[i] >> 4];
		out[2 * i + 1] = d[in[i] & 0xf];
	}
	out[2 * n] = '\0';
}

char *hex_alloc(const void *in, size_t n)
{
	char *out = xmalloc(size_add(size_mul(n, 2), 1));

	if (out)
		hex_encode(in, n, out);
	return out;
}

int hex_nibble(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

bool hex_is_lower(const char *s, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (!(s[i] >= '0' && s[i] <= '9') &&
		    !(s[i] >= 'a' && s[i] <= 'f'))
			return false;
	return true;
}

int hex_decode(const char *hex, __u8 *out, size_t n)
{
	size_t i;

	if (strlen(hex) != size_mul(n, 2))
		return -EINVAL;
	for (i = 0; i < n; i++) {
		int hi = hex_nibble(hex[2 * i]);
		int lo = hex_nibble(hex[2 * i + 1]);

		if (hi < 0 || lo < 0)
			return -EINVAL;
		out[i] = (__u8)((hi << 4) | lo);
	}
	return 0;
}

int hex_decode_max(const char *hex, __u8 *out, size_t cap, size_t *len)
{
	size_t n = strnlen(hex, size_add(size_mul(cap, 2), 1));
	int ret;

	if (n % 2)
		return -EINVAL;
	ret = hex_decode(hex, out, n / 2);
	if (!ret)
		*len = n / 2;
	return ret;
}

int sha256_digest_decode(const char *digest, __u8 out[32])
{
	if (!digest || !str_skip_prefix(&digest, "sha256:"))
		return -EINVAL;
	return hex_decode(digest, out, 32);
}

void sha256_digest_encode(const __u8 in[32],
			  char out[SHA256_DIGEST_STR_SIZE])
{
	memcpy(out, "sha256:", 7);
	hex_encode(in, 32, out + 7);
}
