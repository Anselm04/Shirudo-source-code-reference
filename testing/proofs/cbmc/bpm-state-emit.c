// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_state_emit() of util/bpm_state.c with the JSON writer of util/json.c,
 * for none, one or both of two fixed entries, into LEN bytes: 0 exactly
 * when the state document fits with its NUL, the document then byte for
 * byte, and nothing written past LEN bytes or to the length on a refusal.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/json.c"
#include "../../../util/bpm_state.c"

#define FIX	BPM_PACKAGES_DIR "/fix/1.0.0"
#define OBS	BPM_PACKAGES_DIR "/kernel-obs/2.1.0-rc.1"

static const struct bpm_state_entry entries[] = {
	{ "fix", "1.0.0", "main", FIX },
	{ "kernel-obs", "2.1.0-rc.1", "direct", OBS },
};

#define ENTRY_FIX							\
	"{\"name\":\"fix\",\"version\":\"1.0.0\",\"source\":\"main\","	\
	"\"path\":\"" FIX "\"}"
#define ENTRY_OBS							\
	"{\"name\":\"kernel-obs\",\"version\":\"2.1.0-rc.1\","		\
	"\"source\":\"direct\",\"path\":\"" OBS "\"}"

/* The state document of the first n entries. */
static const char *const document[] = {
	"{\"schema\":1,\"packages\":[]}",
	"{\"schema\":1,\"packages\":[" ENTRY_FIX "]}",
	"{\"schema\":1,\"packages\":[" ENTRY_FIX "," ENTRY_OBS "]}",
};

void harness(void)
{
	char *buf = any_bytes(LEN);
	size_t len, was, size;
	int n, ret;

	__CPROVER_assume(n >= 0 && n < (int)ARRAY_SIZE(document));
	size = strlen(document[n]);
	was = len;
	ret = bpm_state_emit(entries, n, buf, LEN, &len);
	__CPROVER_assert(ret == (size < LEN ? 0 : -E2BIG),
			 "0 exactly when the document fits with its NUL");
	if (ret) {
		__CPROVER_assert(len == was, "no length of a refused document");
		return;
	}
	__CPROVER_assert(len == size && !strcmp(buf, document[n]),
			 "the state document, byte for byte");
}
