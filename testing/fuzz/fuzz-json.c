// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * json_parse() over a schema with every field type, and json_walk()
 * over the same input.
 */

#include <stdlib.h>

#include "fuzz.h"

#include <shirudo/string.h>

#include "json.h"

static int on_elem(void *ctx)
{
	(*(int *)ctx)++;
	return 0;
}

/* Whatever the walk hands over is whole UTF-8 text without a NUL. */
static int check_text(void *ctx, const char *s)
{
	size_t n = strlen(s), w;

	for (size_t i = 0; i < n; i += w) {
		w = utf8_width(s + i, n - i);
		if (!w)
			abort();
	}
	return 0;
}

static const struct json_visitor checker = {
	.key = check_text, .string = check_text,
};

static int on_member(void *ctx, const char *key)
{
	return check_text(ctx, key);
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	char s[64], k[32], v[16], w[16];
	__s64 i = 0, n = 0;
	int b = 0, elems = 0, words = 0;
	struct json_array arr = { on_elem, &elems };
	struct json_array list = { on_elem, &words };
	struct json_map map = { on_member, NULL };
	struct json_field obj[] = {
		{ "k", JSON_T_STRING, k, sizeof(k), 0, NULL, 0 },
		{ "n", JSON_T_INT, &n, 0, 0, NULL, 0 },
	};
	struct json_field elem[] = {
		{ "v", JSON_T_STRING, v, sizeof(v), 0, NULL, 0 },
		{ "o", JSON_T_OBJECT, NULL, 0, 0, obj, ARRAY_SIZE(obj) },
	};
	struct json_field word[] = {
		{ "", JSON_T_STRING, w, sizeof(w), 0, NULL, 0 },
	};
	struct json_field member[] = {
		{ "", JSON_T_ARRAY, &list, 0, 0, word, ARRAY_SIZE(word) },
	};
	struct json_field root[] = {
		{ "s", JSON_T_STRING, s, sizeof(s), 0, NULL, 0 },
		{ "i", JSON_T_INT, &i, 0, 0, NULL, 0 },
		{ "b", JSON_T_BOOL, &b, 0, 0, NULL, 0 },
		{ "o", JSON_T_OBJECT, NULL, 0, 0, obj, ARRAY_SIZE(obj) },
		{ "a", JSON_T_ARRAY, &arr, 0, 0, elem, ARRAY_SIZE(elem) },
		{ "m", JSON_T_MAP, &map, 0, 0, member, ARRAY_SIZE(member) },
	};

	json_parse((const char *)data, size, root, ARRAY_SIZE(root));
	json_walk((const char *)data, size, &checker, NULL);
	return 0;
}
