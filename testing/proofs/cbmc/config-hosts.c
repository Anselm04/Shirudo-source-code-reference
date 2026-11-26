// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * tls_classical_hosts_valid() of util/config.c, the shirudo.conf reader,
 * and dns_name_valid() of util/string.c, which decides each of its names,
 * on values and names of LEN bytes: a value passes exactly when it is
 * empty or names apart by single commas, and a name is valid exactly as
 * RFC 1123 spells a host name that is not a numeric address.
 */

#define PROOF_MEMCPY_BYTEWISE
#include "proof.h"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/config.c"

#define LABEL_MAX	63
#define NAME_MAX_LEN	253

void pr_warn(const char *fmt, ...)
{
}

static char *any_name(void)
{
	char *s = any_bytes(LEN + 1);

	s[LEN] = '\0';
	return s;
}

static bool decimal(char c)
{
	return c >= '0' && c <= '9';
}

static bool hex_digit(char c)
{
	return decimal(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static bool host_char(char c)
{
	return decimal(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       c == '-';
}

/* A label an address parser takes for a number: decimal, or 0x and hex. */
static bool numeric_label(const char *s, size_t n)
{
	bool dec = n, hex = n > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X');
	size_t i;

	for (i = 0; i < n; i++) {
		dec = dec && decimal(s[i]);
		hex = hex && (i < 2 || hex_digit(s[i]));
	}
	return dec || hex;
}

static bool label_valid(const char *s, size_t n)
{
	size_t i;

	if (!n || n > LABEL_MAX || s[0] == '-' || s[n - 1] == '-')
		return false;
	for (i = 0; i < n; i++)
		if (!host_char(s[i]))
			return false;
	return true;
}

/* Labels apart by single dots, not all of them numeric. */
static bool name_valid(const char *s, size_t len)
{
	bool numeric = true;
	size_t start = 0, i;

	if (!len || len > NAME_MAX_LEN)
		return false;
	for (i = 0; i <= len; i++) {
		if (i < len && s[i] != '.')
			continue;
		if (!label_valid(s + start, i - start))
			return false;
		numeric = numeric && numeric_label(s + start, i - start);
		start = i + 1;
	}
	return !numeric;
}

static void names(void)
{
	char *name = any_name();

	__CPROVER_assert(dns_name_valid(name) ==
			 name_valid(name, strlen(name)),
			 "a host name of labels, not a numeric address");
}

/* Empty, or names of one byte or more apart by single commas. */
static bool hosts_valid(const char *val, size_t len)
{
	size_t start = 0, i;

	if (!len)
		return true;
	for (i = 0; i <= len; i++) {
		if (i < len && val[i] != ',')
			continue;
		if (!name_valid(val + start, i - start))
			return false;
		start = i + 1;
	}
	return true;
}

static void hosts(void)
{
	char *val = any_bytes(LEN + 1);

	val[LEN] = '\0';
	__CPROVER_assert(tls_classical_hosts_valid(val) ==
			 hosts_valid(val, strlen(val)),
			 "empty, or names apart by single commas");
}

void harness(void)
{
	names();
	hosts();
}
