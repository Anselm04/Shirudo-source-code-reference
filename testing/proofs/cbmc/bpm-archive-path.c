// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The member names util/bpm_package.c takes from a .bee, for every name of
 * LEN bytes: a path passes when it cannot leave the directory it is put
 * under, and a member is matched only in the archive's top directory.
 */

#include "proof.h"
#include "../../../util/bpm_package.c"

#define MEMBER_MAX	3

/* A component of s that is exactly "." or "..", starting at i. */
static bool dot_component(const char *s, size_t len, size_t i)
{
	size_t n = 0;

	if (i && s[i - 1] != '/')
		return false;
	while (n < 2 && i + n < len && s[i + n] == '.')
		n++;
	return n && (i + n == len || s[i + n] == '/');
}

static bool contained(const char *s, size_t len)
{
	size_t i;

	if (!len || s[0] == '/')
		return false;
	for (i = 0; i < len; i++) {
		if (s[i] == '/' && i + 1 < len && s[i + 1] == '/')
			return false;
		if (dot_component(s, len, i))
			return false;
	}
	return true;
}

static char *string(size_t len, size_t room)
{
	char *s = any_bytes(room + 1);

	__CPROVER_assume(!s[len] && strnlen(s, len) == len);
	return s;
}

void harness(void)
{
	size_t member_len, dir, i;
	char *name, *member;
	bool same;

	name = string(LEN, LEN);
	__CPROVER_assert(bpm_archive_rel_ok(name) == contained(name, LEN),
			 "a name passes exactly when it stays inside");

	__CPROVER_assume(member_len <= MEMBER_MAX);
	member = string(member_len, MEMBER_MAX);
	for (dir = 0; dir < LEN && name[dir] != '/'; dir++)
		;
	same = dir < LEN && LEN - dir - 1 == member_len;
	for (i = 0; same && i < member_len; i++)
		same = name[dir + 1 + i] == member[i];
	__CPROVER_assert(package_member_name_ok(name, member) ==
			 (contained(name, LEN) && contained(member, member_len) &&
			  same),
			 "a member only as the whole path below the top directory");
}
