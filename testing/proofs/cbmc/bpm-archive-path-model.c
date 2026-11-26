// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_archive_rel_ok() and package_member_name_ok() of util/bpm_package.c
 * against the model testing/proofs/lean4/Shirudo/ArchivePath.lean proves
 * keeps every name inside the directory it is resolved below, for names
 * of every length: on every name of LEN bytes and member of up to
 * MEMBER_MAX they decide as relOk and memberNameOk do.
 */

#include <stdbool.h>
#include <zlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "proof.h"
#include "../../../util/string.c"
#include "../../../util/bpm_package.c"

#define MEMBER_MAX	3

/* bad: empty, "." or "..". */
static bool model_bad(const char *c, size_t n)
{
	return !n || (n == 1 && c[0] == '.') ||
	       (n == 2 && c[0] == '.' && c[1] == '.');
}

/* relLoop from p: takeWhile to the next '/', then dropWhile. */
static bool model_rel_loop(const char *s, size_t len, size_t p)
{
	size_t q;

	while (p < len) {
		for (q = p; q < len && s[q] != '/'; q++)
			;
		if (model_bad(s + p, q - p))
			return false;
		if (q == len)
			return true;
		p = q + 1;
	}
	return true;
}

/* relOk. */
static bool model_rel_ok(const char *s, size_t len)
{
	return len && s[0] != '/' && model_rel_loop(s, len, 0);
}

/* memberNameOk. */
static bool model_member_name_ok(const char *name, size_t len,
				 const char *member, size_t member_len)
{
	size_t t;

	for (t = 0; t < len && name[t] != '/'; t++)
		;
	return model_rel_ok(name, len) && t < len && t &&
	       !(len >= 2 && name[0] == '.' && name[1] == '/') &&
	       model_rel_ok(member, member_len) &&
	       len - t - 1 == member_len &&
	       !memcmp(name + t + 1, member, member_len);
}

static char *string(size_t len, size_t room)
{
	char *s = any_bytes(room + 1);

	__CPROVER_assume(!s[len] && strnlen(s, len) == len);
	return s;
}

void harness(void)
{
	char *name, *member;
	size_t member_len;

	name = string(LEN, LEN);
	__CPROVER_assert(bpm_archive_rel_ok(name) == model_rel_ok(name, LEN),
			 "relOk");

	__CPROVER_assume(member_len <= MEMBER_MAX);
	member = string(member_len, MEMBER_MAX);
	__CPROVER_assert(package_member_name_ok(name, member) ==
			 model_member_name_ok(name, LEN, member, member_len),
			 "memberNameOk");
}
