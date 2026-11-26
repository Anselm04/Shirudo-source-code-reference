// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The member paths bpm build takes from a Beefile, for every target of LEN
 * bytes: tools/shirudo-build/bpm-build.c takes exactly the file paths the
 * archive reader of util/bpm_package.c takes, each of them once and none
 * above or below one it took, which the extractor could not unpack beside
 * it; bpm-beefile-tables has the members bpm build writes itself.
 */

/* As proof.h, before the system headers can include <ctype.h>. */
#define __NO_CTYPE 1

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define PROOF_MEMCPY_BYTEWISE
#include "proof.h"
#include "../../../util/string.c"
#include "../../../util/bpm_package.c"
#include "../../../tools/shirudo-build/bpm-build.c"

/* Targets up to this long also join a table; longer ones cost minutes. */
#define ADD_MAX		4

static char *string(size_t len)
{
	char *s = any_bytes(len + 1);

	__CPROVER_assume(strnlen(s, len) == len);
	s[len] = '\0';
	return s;
}

/* A target is a path the reader extracts, and one that names a file. */
static bool target_taken(const char *target)
{
	bool taken = !build_target_ok(target);

	__CPROVER_assert(taken == (bpm_archive_rel_ok(target) &&
				   target[LEN - !!LEN] != '/'),
			 "exactly the reader's paths without a final slash");
	return taken;
}

/* Whether path is dir, a slash and more: a file where dir is one. */
static bool below(const char *dir, const char *path)
{
	size_t n = strlen(dir);

	return strlen(path) > n && !memcmp(path, dir, n) && path[n] == '/';
}

/* A target joins the one seen before it, any string or none. */
static void target_added(const char *target, bool taken)
{
	char seen[2][PATH_MAX] = {};
	size_t n = 1, i, j;
	bool twice, nested;
	int ret;

	for (j = 0; j <= LEN; j++) {
		char any;

		seen[0][j] = any;
	}
	__CPROVER_assume(i <= LEN);
	twice = !strcmp(seen[0], target);
	nested = below(seen[0], target) || below(target, seen[0]);
	ret = build_add_target(seen, &n, target);
	__CPROVER_assert(!ret == (taken && !twice && !nested),
			 "a path taken once, none above or below one taken");
	if (ret) {
		__CPROVER_assert(n == 1, "a refused target is not counted");
		return;
	}
	__CPROVER_assert(n == 2 && seen[1][i] == target[i],
			 "the target seen from now on");
}

void harness(void)
{
	char *target;
	bool taken;

	target = string(LEN);
	taken = target_taken(target);
	if (LEN <= ADD_MAX)
		target_added(target, taken);
}
