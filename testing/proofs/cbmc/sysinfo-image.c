// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The image identity parsers of util/sysinfo.c, whose values a keepalive
 * carries: an os-release value of LEN bytes unquoted, the last assignment
 * of a key in a text of LEN bytes, and the root a command line names, for
 * hashes of 64 bytes and, at LEN 1 and 2, of 63 and 65.
 */

#include "proof.h"
#include "../../../util/sysinfo.c"

#define HASH_LEN	(SYSINFO_IMAGE_ROOT_MAX - 1)

static bool printable(char c)
{
	return (__u8)c >= 0x20 && (__u8)c <= 0x7e;
}

static bool escapable(char c)
{
	return c == '"' || c == '\\' || c == '$' || c == '`';
}

/* os-release(5) on short values: one quote pair, escapes in double quotes. */
static void unquotes(void)
{
	char value[LEN ? LEN : 1], out[SYSINFO_IMAGE_VALUE_MAX];
	char want[LEN ? LEN : 1];
	size_t start = 0, end = LEN, n = 0;
	bool dq = false, ok = true;
	int ret;

	if (LEN >= 2 && value[0] == value[LEN - 1] &&
	    (value[0] == '"' || value[0] == '\'')) {
		dq = value[0] == '"';
		start = 1;
		end = LEN - 1;
	}
	for (size_t i = start; i < end; i++) {
		char c = value[i];

		if (dq && c == '\\' && i + 1 < end && escapable(value[i + 1]))
			c = value[++i];
		ok = ok && printable(c);
		want[n++] = c;
	}
	ret = os_release_unquote(value, LEN, out);
	__CPROVER_assert(!ret == (ok && n > 0),
			 "taken exactly when 1 or more printable bytes remain");
	if (ret)
		return;
	__CPROVER_assert(!out[n], "terminated after the value");
	for (size_t i = 0; i < n; i++)
		__CPROVER_assert(out[i] == want[i], "the unquoted value");
}

/* The 255 bytes a value holds, and no more. */
static void bounds(void)
{
	static char value[SYSINFO_IMAGE_VALUE_MAX + 2];
	char out[SYSINFO_IMAGE_VALUE_MAX];

	memset(value, 'a', sizeof(value));
	__CPROVER_assert(!os_release_unquote(value, SYSINFO_IMAGE_VALUE_MAX - 1,
					     out) &&
			 !out[SYSINFO_IMAGE_VALUE_MAX - 1],
			 "255 bytes taken");
	__CPROVER_assert(os_release_unquote(value, SYSINFO_IMAGE_VALUE_MAX,
					    out) == -EINVAL,
			 "256 bytes refused");
	value[0] = '"';
	value[SYSINFO_IMAGE_VALUE_MAX] = '"';
	__CPROVER_assert(!os_release_unquote(value, SYSINFO_IMAGE_VALUE_MAX + 1,
					     out),
			 "255 bytes in quotes taken");
}

/* Of the lines "K=..." of a text the last one counts, or none. */
static void last_assignment(void)
{
	char text[LEN ? LEN : 1], out[SYSINFO_IMAGE_VALUE_MAX];
	char want[SYSINFO_IMAGE_VALUE_MAX] = "";
	const char *value = NULL;
	size_t value_len = 0, line = 0, i;

	for (i = 0; i <= LEN; i++) {
		if (i < LEN && text[i] != '\n')
			continue;
		if (i - line >= 2 && text[line] == 'K' &&
		    text[line + 1] == '=') {
			value = text + line + 2;
			value_len = i - line - 2;
		}
		line = i + 1;
	}
	if (value && os_release_unquote(value, value_len, want))
		want[0] = '\0';
	os_release_value(text, LEN, "K", out);
	__CPROVER_assert(!strcmp(out, want), "the last assignment's value");
}

static bool all_hex(const char *h, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (!isxdigit((__u8)h[i]))
			return false;
	return true;
}

static size_t put(char *dst, size_t at, const char *src, size_t n)
{
	memcpy(dst + at, src, n);
	return at + n;
}

/*
 * roothash= wins over usrhash= whether or not it is a hash, and the root
 * is the one it names in lowercase, when it is 64 digits, or none. A value
 * holds no separator, so that the arguments are those the line was built
 * from.
 */
static void command_line(size_t hash_len)
{
	char root[HASH_LEN + 1], usr[HASH_LEN + 1];
	char line[2 + 8 + HASH_LEN + 1 + 1 + 9 + HASH_LEN + 1];
	char out[SYSINFO_IMAGE_ROOT_MAX];
	bool junk, has_usr, has_root;
	const char *named;
	size_t at = 0;

	for (size_t i = 0; i < hash_len; i++)
		__CPROVER_assume(!cmdline_space(root[i]) &&
				 !cmdline_space(usr[i]));

	if (junk)
		at = put(line, at, "x ", 2);
	if (has_usr) {
		at = put(line, at, "usrhash=", 8);
		at = put(line, at, usr, hash_len);
		at = put(line, at, " ", 1);
	}
	if (has_root) {
		at = put(line, at, "roothash=", 9);
		at = put(line, at, root, hash_len);
	}
	cmdline_image_root(line, at, out);
	named = has_root ? root : has_usr ? usr : NULL;
	if (!named || hash_len != HASH_LEN || !all_hex(named, hash_len)) {
		__CPROVER_assert(!out[0], "no root");
		return;
	}
	__CPROVER_assert(!out[HASH_LEN], "64 digits");
	for (size_t i = 0; i < HASH_LEN; i++)
		__CPROVER_assert(out[i] == tolower((__u8)named[i]),
				 "the named root in lowercase");
}

void harness(void)
{
	unquotes();
	last_assignment();
	if (!LEN) {
		bounds();
		command_line(HASH_LEN);
	}
	if (LEN == 1 || LEN == 2)
		command_line(LEN == 1 ? HASH_LEN - 1 : HASH_LEN + 1);
}
