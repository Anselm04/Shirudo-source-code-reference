// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * set_owner_auth() of util/config.c, the shirudo.conf reader, on every
 * tpm.owner_auth value of LEN bytes and any earlier value: it stores the
 * bytes an even run of hex digits after "hex:" spells, or the text
 * itself, each only where it fits, and a refusal leaves the earlier value.
 */

#define PROOF_MEMCPY_BYTEWISE
#include "proof.h"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/config.c"

#define AUTH_MAX	OWNER_AUTH_MAX

/*
 * A value longer than SYMBOLIC bytes, there to reach the 256-byte limit
 * of a passphrase, is any SYMBOLIC bytes but NUL followed by letters, all
 * LEN bytes of it; the shorter ones are any bytes and end anywhere.
 */
#define SYMBOLIC	8

void pr_warn(const char *fmt, ...)
{
}

static char *any_value(void)
{
	char *s = any_bytes(LEN + 1);
	size_t i;

	if (LEN > SYMBOLIC)
		for (i = 0; i < SYMBOLIC; i++)
			__CPROVER_assume(s[i]);
	for (i = SYMBOLIC; i < LEN; i++)
		s[i] = 'p';
	s[LEN] = '\0';
	return s;
}

static bool hex_run(const char *s, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (hex_nibble(s[i]) < 0)
			return false;
	return !(n % 2);
}

/*
 * Each byte is checked at an index k of any value below AUTH_MAX, one
 * read where a loop over all of them would cost minutes.
 */
void harness(void)
{
	char *val = any_value(), was;
	struct config cfg;
	size_t had, n, k;

	__CPROVER_assume(cfg.tpm_owner_auth_len <= AUTH_MAX && k < AUTH_MAX);
	had = cfg.tpm_owner_auth_len;
	was = cfg.tpm_owner_auth[k];
	n = strlen(val);
	set_owner_auth(&cfg, val);
	if (!str_has_prefix(val, "hex:")) {
		if (n > AUTH_MAX) {
			__CPROVER_assert(cfg.tpm_owner_auth_len == had &&
					 cfg.tpm_owner_auth[k] == was,
					 "a passphrase too long leaves the earlier value");
			return;
		}
		__CPROVER_assert(cfg.tpm_owner_auth_len == n &&
				 (k >= n || cfg.tpm_owner_auth[k] == val[k]),
				 "a passphrase as it stands");
		return;
	}
	if (!hex_run(val + 4, n - 4) || (n - 4) / 2 > AUTH_MAX) {
		__CPROVER_assert(cfg.tpm_owner_auth_len == had &&
				 cfg.tpm_owner_auth[k] == was,
				 "a refusal leaves the earlier value");
		return;
	}
	__CPROVER_assert(cfg.tpm_owner_auth_len == (n - 4) / 2 &&
			 (k >= (n - 4) / 2 ||
			  (__u8)cfg.tpm_owner_auth[k] ==
			  (hex_nibble(val[4 + 2 * k]) << 4 |
			   hex_nibble(val[5 + 2 * k]))),
			 "the bytes the hex digits spell");
}
