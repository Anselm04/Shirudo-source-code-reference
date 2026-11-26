// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The version bpm build takes, on every string of LEN bytes:
 * tools/shirudo-build/bpm-build.c takes only versions util/bpm_oci.c lets
 * through on the target, and <name>-<version> is one directory to the
 * archive reader of util/bpm_package.c.
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
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "proof.h"
#include "../../../util/string.c"
#include "../../../util/bpm_oci.c"
#include "../../../util/bpm_package.c"
#include "../../../tools/shirudo-build/bpm-build.c"

static char *string(size_t len)
{
	char *s = any_bytes(len + 1);

	__CPROVER_assume(strnlen(s, len) == len);
	s[len] = '\0';
	return s;
}

void harness(void)
{
	char top[1 + 1 + LEN + 1];
	char *name, *version;

	version = string(LEN);
	if (!build_version_ok(version))
		return;
	__CPROVER_assert(bpm_version_ok(version),
			 "a version the target takes");
	/* build_archive() names the one directory of the archive so. */
	name = string(1);
	if (!build_name_ok(name))
		return;
	__CPROVER_assert(strsprintf(top, sizeof(top), "%s-%s", name, version) ==
			 LEN + 2 && bpm_archive_rel_ok(top) &&
			 !strchr(top, '/'),
			 "one component the archive reader takes");
}
