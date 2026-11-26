// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * A line of a kernel configuration.
 */

#include <ctype.h>
#include <string.h>

#include <shirudo/string.h>
#include <shirudo/types.h>

#include "kconfig.h"

static char *trimmed(char *text)
{
	char *end;

	while (isspace((__u8)*text))
		text++;
	end = text + strlen(text);
	while (end > text && isspace((__u8)end[-1]))
		*--end = '\0';
	return text;
}

/* CONFIG_ and a name after it. */
static bool option_name(const char *key)
{
	size_t n = str_has_prefix(key, "CONFIG_");

	return n && key[n];
}

static const char *unquoted(char *text)
{
	size_t len = strlen(text);

	if (len < 2 || text[0] != '"' || text[len - 1] != '"')
		return text;
	text[len - 1] = '\0';
	return text + 1;
}

bool kconfig_line(char *line, const char **key, const char **value)
{
	static const char not_set[] = " is not set";
	char *name = trimmed(line), *cut;
	const char *text;

	if (str_has_prefix(name, "# CONFIG_")) {
		name += strlen("# ");
		cut = span_find(name, strlen(name), not_set);
		if (!cut || cut[strlen(not_set)])
			return false;
		*cut = '\0';
		text = "n";
	} else {
		cut = strchr(name, '=');
		if (!cut)
			return false;
		*cut = '\0';
		name = trimmed(name);
		text = unquoted(trimmed(cut + 1));
	}
	if (!option_name(name))
		return false;
	*key = name;
	*value = text;
	return true;
}
