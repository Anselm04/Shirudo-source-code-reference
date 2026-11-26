// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The package name bpm build takes from a Beefile, on every string of up
 * to NAME_MAX bytes: build_name_ok() of tools/shirudo-build/bpm-build.c
 * takes exactly the names util/bpm_oci.c takes as a package's on the
 * target, which the repository index takes too.
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
#include "../../../tools/shirudo-build/bpm-build.c"

#define NAME_MAX	(BPM_MAX_NAME + 1)

void harness(void)
{
	char *s = any_bytes(NAME_MAX + 1);
	bool taken;

	__CPROVER_assume(!s[NAME_MAX]);
	taken = build_name_ok(s);
	__CPROVER_assert(taken == bpm_package_name_ok(s),
			 "exactly the names of a package");
	__CPROVER_assert(!taken || bpm_name_ok(s),
			 "which the repository index takes too");
}
