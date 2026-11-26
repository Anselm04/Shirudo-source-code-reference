// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * on_state_entry() of util/bpm_state.c on any entry with a name and
 * version of up to SHORT_MAX bytes, read into an empty table (LEN 0) or a
 * full one (LEN 1): kept exactly when name, version and source are valid
 * and the path is theirs under the packages directory and fits its buffer,
 * and the next read into a cleared one.
 */

/* util/string.c is included behind a file that includes its header. */
#define STRING_INTERNAL

/*
 * A table entry of PATH_MAX bytes costs CBMC minutes and gigabytes at
 * every copy. The path buffer here is one that some of the paths outgrow;
 * none outgrows the real one, which the last line of this file checks.
 */
#include <limits.h>
enum { SYSTEM_PATH_MAX = PATH_MAX };
#undef PATH_MAX
#define PATH_MAX	40

#include "proof.h"
#include "../../../util/bpm_state.c"
#include "../../../util/bpm_oci.c"
#include "../../../util/string.c"

#define SHORT_MAX	6

static void terminate(char *s, size_t size)
{
	__CPROVER_assume(!s[size - 1]);
}

/* BPM_PACKAGES_DIR, the name and the version, a '/' between them. */
static bool path_of(const struct bpm_state_entry *e)
{
	size_t dir = strlen(BPM_PACKAGES_DIR "/"), name = strlen(e->name);

	return dir + name + 1 + strlen(e->version) < sizeof(e->path) &&
	       !memcmp(e->path, BPM_PACKAGES_DIR "/", dir) &&
	       !memcmp(e->path + dir, e->name, name) &&
	       e->path[dir + name] == '/' &&
	       !strcmp(e->path + dir + name + 1, e->version);
}

void harness(void)
{
	struct bpm_state_entry items[1], was;
	struct state_sink s;
	size_t i;
	int ret;

	s.items = items;
	s.n = LEN ? BPM_MAX_STATE : 0;
	terminate(s.scratch.name, SHORT_MAX + 1);
	terminate(s.scratch.version, SHORT_MAX + 1);
	terminate(s.scratch.source, sizeof(s.scratch.source));
	terminate(s.scratch.path, sizeof(s.scratch.path));
	was = s.scratch;
	ret = on_state_entry(&s);
	__CPROVER_assert(!ret == (!LEN && bpm_name_ok(was.name) &&
				  bpm_version_ok(was.version) &&
				  bpm_name_ok(was.source) && path_of(&was)),
			 "a valid entry at its own path, while room");
	if (ret) {
		__CPROVER_assert(ret == (LEN ? -E2BIG : -EINVAL) &&
				 s.n == (LEN ? BPM_MAX_STATE : 0),
				 "a refused entry is not counted");
		return;
	}
	__CPROVER_assume(i < BPM_MAX_NAME);
	__CPROVER_assert(s.n == 1 && items[0].name[i] == was.name[i] &&
			 items[0].version[i] == was.version[i] &&
			 items[0].source[i] == was.source[i] &&
			 items[0].path[i % PATH_MAX] == was.path[i % PATH_MAX],
			 "the entry kept as read");
	__CPROVER_assert(!s.scratch.name[i] && !s.scratch.version[i] &&
			 !s.scratch.source[i] && !s.scratch.path[i % PATH_MAX],
			 "the next entry read into a cleared one");
}

BUILD_BUG_ON(sizeof(BPM_PACKAGES_DIR) + 2 * BPM_MAX_NAME > SYSTEM_PATH_MAX);
