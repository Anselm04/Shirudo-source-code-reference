// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * build_parse_spec() of tools/shirudo-build/bpm-build.c from every count
 * of tables up to its limit: one more [[files]], [[upatches]], rodata or
 * policy table is counted below the limit and refused at it, and a
 * sub-table without its [[upatches]] or a target that is one of bpm
 * build's own members, or lies below one, is refused. LEN picks the case.
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

#include "proof.h"
#include "../../../util/string.c"
#include "../../../tools/shirudo-build/bpm-build.c"

enum {
	FILES, UPATCHES, RODATA, POLICY, STRAY_RODATA, STRAY_POLICY,
	STRAY_TREE, OWN_MEMBERS,
};

static struct bpm_build_spec spec;

/* The tables of an upatch, which the reader allocates at their limits. */
void *xcalloc(size_t nmemb, size_t size)
{
	static struct bpm_build_policy policies[BPM_BUILD_MAX_POLICIES];
	static struct bpm_build_rodata rodata[BPM_BUILD_MAX_RODATA];

	if (nmemb == BPM_BUILD_MAX_RODATA && size == sizeof(rodata[0]))
		return rodata;
	__CPROVER_assert(nmemb == BPM_BUILD_MAX_POLICIES &&
			 size == sizeof(policies[0]), "rodata or policies");
	return policies;
}

/*
 * The Beefile has no [package] name, so the reader refuses it once every
 * line is read, and what it counted until then stays to be looked at.
 */
static void counted(char *body, size_t *count, size_t limit)
{
	size_t was = *count;
	int ret;

	__CPROVER_assume(was <= limit);
	ret = build_parse_spec(&spec, body);
	__CPROVER_assert(ret == (was == limit ? -E2BIG : -EINVAL),
			 "refused at the limit, as too many");
	__CPROVER_assert(*count == was + (was < limit),
			 "one more below the limit, none at it");
}

static void stray(char *body, int error)
{
	__CPROVER_assert(build_parse_spec(&spec, body) == error &&
			 !spec.n_upatches && !spec.upatches[0].n_rodata &&
			 !spec.upatches[0].n_policies &&
			 !spec.upatches[0].tree.present,
			 "a sub-table without its upatch refused, nothing counted");
}

/* The members bpm build writes itself, as the package format names them. */
static void own_members_refused(void)
{
	static const char *const own[] = {
		"Beefile", "README.md", "cert.der", "build-environment.json",
	};
	static const char *const below[] = {
		"Beefile/a", "README.md/a", "cert.der/a",
		"build-environment.json/a",
	};
	char seen[1][PATH_MAX];
	size_t n = 0, i;

	for (i = 0; i < ARRAY_SIZE(own); i++)
		__CPROVER_assert(build_add_target(seen, &n, own[i]) == -EEXIST &&
				 build_add_target(seen, &n, below[i]) == -EEXIST &&
				 !n, "no target is one of bpm build's own, or below one");
}

void harness(void)
{
	char files[] = "[[files]]", upatches[] = "[[upatches]]";
	char rodata[] = "[[upatches]]\n[[upatches.rodata]]";
	char policy[] = "[[upatches]]\n[[upatches.policy]]";
	char stray_rodata[] = "[[upatches.rodata]]";
	char stray_policy[] = "[[upatches.policy]]";
	char stray_tree[] = "[upatches.tree]";
	struct bpm_build_upatch *u = &spec.upatches[0];
	size_t n;

	switch (LEN) {
	case FILES:
		spec.n_files = n;
		counted(files, &spec.n_files, BPM_BUILD_MAX_ENTRIES);
		break;
	case UPATCHES:
		spec.n_upatches = n;
		counted(upatches, &spec.n_upatches, BPM_BUILD_MAX_ENTRIES);
		break;
	case RODATA:
		/* A table the reader allocated holds what it counted. */
		u->n_rodata = n;
		if (n)
			u->rodata = xcalloc(BPM_BUILD_MAX_RODATA,
					    sizeof(*u->rodata));
		counted(rodata, &u->n_rodata, BPM_BUILD_MAX_RODATA);
		break;
	case POLICY:
		u->n_policies = n;
		if (n)
			u->policies = xcalloc(BPM_BUILD_MAX_POLICIES,
					      sizeof(*u->policies));
		counted(policy, &u->n_policies, BPM_BUILD_MAX_POLICIES);
		break;
	case STRAY_RODATA:
		stray(stray_rodata, -E2BIG);
		break;
	case STRAY_POLICY:
		stray(stray_policy, -E2BIG);
		break;
	case STRAY_TREE:
		stray(stray_tree, -EINVAL);
		break;
	default:
		own_members_refused();
	}
}
