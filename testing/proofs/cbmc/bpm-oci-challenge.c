// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * parse_challenge() of util/bpm_oci.c, on a registry's WWW-Authenticate
 * value of up to TEXT_MAX bytes: it takes only a challenge whose scheme is
 * the whole token Bearer, with a realm, each value it takes is a quoted
 * one of the challenge, and every value is terminated inside its buffer,
 * as long as fits it or one more.
 */

#include "proof.h"
#include "../../../util/bpm_oci.c"

#define TEXT_MAX	17
#define REALM_MAX	2
#define OUT_MAX		3

static char *text(void)
{
	char *s = any_bytes(TEXT_MAX + 1);

	__CPROVER_assume(!s[TEXT_MAX]);
	return s;
}

static bool terminated(const char *s, size_t size)
{
	return memchr(s, '\0', size);
}

/* key="value" in s, value its whole quoted text. */
static bool quoted_after(const char *s, size_t len, const char *key,
			 const char *value)
{
	size_t k = strlen(key), v = strlen(value), i, j;
	bool match;

	for (i = 0; i + k + v + 2 <= len; i++) {
		match = s[i + k] == '=' && s[i + k + 1] == '"' &&
			s[i + k + 2 + v] == '"';
		for (j = 0; match && j < k; j++)
			match = s[i + j] == key[j];
		for (j = 0; match && j < v; j++)
			match = s[i + k + 2 + j] == value[j];
		if (match)
			return true;
	}
	return false;
}

void harness(void)
{
	char realm[REALM_MAX] = {}, service[OUT_MAX] = {}, scope[1] = {};
	char *header = text();
	size_t len = strlen(header);
	int ret;

	ret = parse_challenge(header, realm, sizeof(realm), service,
			      sizeof(service), scope, sizeof(scope));
	__CPROVER_assert(terminated(realm, sizeof(realm)) &&
			 terminated(service, sizeof(service)) &&
			 terminated(scope, sizeof(scope)),
			 "every value terminated inside its buffer");
	if (ret)
		return;
	__CPROVER_assert(str_has_prefix_nocase(header, "Bearer") &&
			 (header[6] == ' ' || !header[6]),
			 "only a Bearer challenge, its scheme a whole token");
	__CPROVER_assert(realm[0] && quoted_after(header, len, "realm", realm),
			 "a realm, quoted in the challenge");
	__CPROVER_assert(!service[0] ||
			 quoted_after(header, len, "service", service),
			 "a service quoted in the challenge, if any");
	__CPROVER_assert(!scope[0] || quoted_after(header, len, "scope", scope),
			 "a scope quoted in the challenge, if any");
}
