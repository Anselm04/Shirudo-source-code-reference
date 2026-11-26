// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_upatch_member() and bpm_upatch_pair() of util/bpm_package.c, which
 * decide what install loads and uninstall unloads, on every name of LEN
 * bytes: the suffix alone decides, a pair is refused exactly when it does
 * not fit, and a pair turns back into its name.
 */

#include <stdbool.h>
#include <zlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define PROOF_MEMCPY_BYTEWISE
#include "proof.h"
#include "../../../util/string.c"
#include "../../../util/bpm_package.c"

static bool ends_with(const char *s, size_t len, const char *suffix)
{
	size_t n = strlen(suffix);

	return len > n && !memcmp(s + len - n, suffix, n);
}

void harness(void)
{
	enum bpm_upatch_member kind, back;
	char out[LEN + 8], again[LEN + 8];
	bool plain, unload, upatch;
	size_t cap, room, n;
	char *name;
	int ret;

	name = any_bytes(LEN);
	kind = bpm_upatch_member(name, LEN);
	plain = LEN && name[0] != '.' && !memchr(name, '\0', LEN);
	unload = plain && ends_with(name, LEN, ".unload.upatch");
	upatch = plain && ends_with(name, LEN, ".upatch");
	__CPROVER_assert(kind == (unload ? BPM_UPATCH_UNLOAD :
				  upatch ? BPM_UPATCH_LOAD : BPM_UPATCH_OTHER),
			 "the suffix alone decides");

	__CPROVER_assume(cap <= sizeof(out));
	/* The other half's name and its NUL: 7 bytes more, or 7 less. */
	room = LEN + 8 - (kind == BPM_UPATCH_UNLOAD ? 14 : 0);
	ret = bpm_upatch_pair(name, LEN, out, cap);
	__CPROVER_assert(ret == (kind == BPM_UPATCH_OTHER ? -EINVAL :
				 cap < room ? -ENAMETOOLONG : 0),
			 "refused exactly when no pair or when it cannot fit");
	if (ret)
		return;
	n = strnlen(out, cap);
	__CPROVER_assert(n < cap, "terminated");
	back = bpm_upatch_member(out, n);
	__CPROVER_assert(back != BPM_UPATCH_OTHER && back != kind,
			 "the other half of the pair");
	__CPROVER_assert(!bpm_upatch_pair(out, n, again, sizeof(again)) &&
			 strnlen(again, sizeof(again)) == LEN &&
			 !memcmp(again, name, LEN),
			 "which pairs back to the name");
}
