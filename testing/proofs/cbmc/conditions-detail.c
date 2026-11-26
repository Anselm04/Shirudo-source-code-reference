// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * set_detail() of util/conditions.c, which formats the details that list
 * names, on every text of up to LEN bytes, the long ones behind a filler:
 * the whole text where the detail holds it, its start and "..." where
 * not, and "?" once the text outgrows the buffer it is formatted in.
 */

/* util/string.c is included behind a file that includes its header. */
#define STRING_INTERNAL

#include "proof.h"
#include "../../../util/conditions.c"
#include "../../../util/string.c"

/* The buffer set_detail() formats in. */
#define TEXT_MAX	1024

/*
 * A thousand bytes of any contents cost CBMC minutes. A text that long
 * starts with 832 bytes the format itself holds, which is as good a start
 * to cut as any, and ends in up to 192 of any contents.
 */
#define X16		"xxxxxxxxxxxxxxxx"
#define X64		X16 X16 X16 X16
#define X256		X64 X64 X64 X64
#if LEN > 832
#define FILLER		X256 X256 X256 X64
#else
#define FILLER		""
#endif
#define FILLED		(sizeof(FILLER) - 1)

void harness(void)
{
	char *names = any_bytes(LEN - FILLED + 1);
	struct condition c;
	size_t len, room;

	names[LEN - FILLED] = '\0';
	len = FILLED + strlen(names);
	room = sizeof(c.detail) - 1;
	set_detail(&c, "ALERT", FILLER "%s", names);
	__CPROVER_assert(!strcmp(c.status, "ALERT"), "the status given");
	if (len <= room)
		__CPROVER_assert(!strcmp(c.detail, names),
				 "the whole text where the detail holds it");
	else if (len < TEXT_MAX)
		__CPROVER_assert(!memcmp(c.detail, FILLED ? FILLER : names,
					 room - 3) &&
				 !strcmp(c.detail + room - 3, "..."),
				 "the start of a longer text and three dots");
	else
		__CPROVER_assert(!strcmp(c.detail, "?"),
				 "no text that outgrows the formatter");
}
