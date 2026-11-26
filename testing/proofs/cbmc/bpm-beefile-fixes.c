// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * build_parse_fixes() of tools/shirudo-build/bpm-build.c on an array of
 * three IDs of up to LEN bytes: taken exactly when each is a nonempty run
 * of [A-Za-z0-9._:-] and no two are the same, then kept in ascending
 * order; a table that gives fixes twice is refused.
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

#define IDS	3
#define SLOT	(LEN + 3)

static char value[1 + IDS * SLOT + 1];

void pr_err(const char *fmt, ...)
{
}

/* CBMC does not model qsort(). */
void qsort(void *base, size_t nmemb, size_t size,
	   int (*compare)(const void *, const void *))
{
	char (*row)[TREE_STRING_MAX] = base, held[TREE_STRING_MAX];

	__CPROVER_assert(size == TREE_STRING_MAX, "rows of strings");
	for (size_t i = 1; i < nmemb; i++) {
		for (size_t j = i; j && compare(row[j - 1], row[j]) > 0; j--) {
			memcpy(held, row[j], size);
			memcpy(row[j], row[j - 1], size);
			memcpy(row[j - 1], held, size);
		}
	}
}

static bool fix_char(char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
	       (c >= '0' && c <= '9') || c == '.' || c == '_' || c == ':' ||
	       c == '-';
}

/*
 * Blanks pad each ID's slot after its closing quote, so that where an ID
 * starts does not depend on the lengths of those before it.
 */
static void any_array(char ids[IDS][LEN + 1], const size_t lens[IDS])
{
	size_t at = 0;

	value[at++] = '[';
	for (int i = 0; i < IDS; i++) {
		value[at++] = '"';
		for (size_t k = 0; k <= LEN; k++) {
			if (k < lens[i])
				__CPROVER_assume(ids[i][k] && ids[i][k] != '"' &&
						 ids[i][k] != '\\');
			else
				ids[i][k] = '\0';
			value[at++] = k < lens[i] ? ids[i][k] :
				      k == lens[i] ? '"' : ' ';
		}
		value[at++] = i + 1 < IDS ? ',' : ']';
	}
	value[at] = '\0';
}

/*
 * CBMC 5.95 reads a char at an index that depends on the data, as
 * bpm_fix_id_ok() does, from the first member of an object whose type
 * starts with an array of char, as struct bpm_fixes does: held behind
 * another member, each row is read where it is.
 */
static struct {
	int before;
	struct bpm_fixes fixes;
} held;

void harness(void)
{
	struct bpm_fixes *fixes = &held.fixes;
	char ids[IDS][LEN + 1];
	bool valid = true;
	size_t lens[IDS];
	int ret;

	for (int i = 0; i < IDS; i++)
		__CPROVER_assume(lens[i] <= LEN);
	any_array(ids, lens);
	for (int i = 0; i < IDS; i++) {
		valid = valid && lens[i];
		for (size_t k = 0; k < lens[i]; k++)
			valid = valid && fix_char(ids[i][k]);
		for (int j = 0; j < i; j++)
			valid = valid && strcmp(ids[i], ids[j]) != 0;
	}
	ret = build_parse_fixes(value, fixes);
	__CPROVER_assert(!ret == valid,
			 "taken exactly when each ID is a nonempty run of [A-Za-z0-9._:-], none twice");
	if (ret)
		return;
	__CPROVER_assert(fixes->n == IDS, "every ID kept");
	for (int i = 0; i < IDS; i++) {
		bool given = false;

		for (int j = 0; j < IDS; j++)
			given = given || !strcmp(fixes->ids[i], ids[j]);
		__CPROVER_assert(given, "each one of those given");
		__CPROVER_assert(!i || strcmp(fixes->ids[i - 1], fixes->ids[i]) < 0,
				 "in ascending order");
	}
	__CPROVER_assert(build_parse_fixes(value, fixes) == -EINVAL &&
			 fixes->n == IDS, "fixes given twice in one table refused");
}
