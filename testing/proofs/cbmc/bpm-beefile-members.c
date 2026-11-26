// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * build_entry_name() of tools/shirudo-build/bpm-build.c, which names every
 * member bpm build writes, on every target of LEN bytes: the archive's
 * directory, a slash and the target, where the readers of
 * util/bpm_package.c find the member, or nothing when it does not fit.
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

/* The archive's directory, <name>-<version>, here of two bytes. */
#define TOP		2
#define NAME_MAX_LEN	(TOP + 1 + LEN)

static char *string(size_t len)
{
	char *s = any_bytes(len + 1);

	__CPROVER_assume(strnlen(s, len) == len);
	s[len] = '\0';
	return s;
}

void harness(void)
{
	char name[NAME_MAX_LEN + 2], was;
	char *top, *target;
	size_t cap, i;
	bool taken;
	int ret;

	top = string(TOP);
	target = string(LEN);
	/* One component, as bpm-beefile-names shows of <name>-<version>. */
	__CPROVER_assume(bpm_archive_rel_ok(top) && !strchr(top, '/'));
	__CPROVER_assume(cap <= sizeof(name) && i < sizeof(name));
	was = name[i];
	ret = build_entry_name(name, cap, top, target);
	__CPROVER_assert(!ret == (cap > NAME_MAX_LEN),
			 "refused exactly when it does not fit");
	if (ret) {
		__CPROVER_assert(name[i] == was, "a refusal writes nothing");
		return;
	}
	__CPROVER_assert(!name[NAME_MAX_LEN] && !memcmp(name, top, TOP) &&
			 name[TOP] == '/' && !memcmp(name + TOP + 1, target, LEN),
			 "the directory, a slash and the target, terminated");
	taken = !build_target_ok(target);
	__CPROVER_assert(!taken || package_member_name_ok(name, target),
			 "a target bpm build takes, found under its name");
	__CPROVER_assert(LEN || (bpm_archive_rel_ok(name) && name[TOP] == '/'),
			 "the directory's own entry a path the reader takes");
}
