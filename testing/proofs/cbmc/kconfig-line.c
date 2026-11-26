// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * kconfig_line() of util/kconfig.c on every line of up to LEN bytes: it
 * reads and writes nothing outside the line, a name it gives is CONFIG_
 * and more and lies in the line, a value lies in the line or is the "n"
 * of an option not set, and a comment sets an option only as one that
 * is not set.
 */

#include "proof.h"
#include "../../../util/string.c"
#include "../../../util/kconfig.c"

void harness(void)
{
	const char *key = NULL, *value = NULL;
	char *line = any_bytes(LEN + 1);
	bool comment = false;
	size_t i;

	__CPROVER_assume(!line[LEN]);
	for (i = 0; i < LEN && isspace((__u8)line[i]); i++)
		;
	comment = line[i] == '#';
	if (!kconfig_line(line, &key, &value)) {
		__CPROVER_assert(!key && !value, "no option, no name or value");
		return;
	}
	__CPROVER_assert(__CPROVER_same_object(key, line) &&
			 !strncmp(key, "CONFIG_", strlen("CONFIG_")) &&
			 key[strlen("CONFIG_")], "a name after CONFIG_, in the line");
	if (comment) {
		__CPROVER_assert(!__CPROVER_same_object(value, line) &&
				 value[0] == 'n' && !value[1],
				 "a comment sets an option only as not set");
		return;
	}
	__CPROVER_assert(__CPROVER_same_object(value, line),
			 "a value in the line");
}
