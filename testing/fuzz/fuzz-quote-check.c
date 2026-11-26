// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * One row of shirudo-quote-check as a backend hands it over: its verdict,
 * the fields a row needs for any verdict but malformed, and the line the
 * verdict is written as, which must read back as JSON.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"

#include <shirudo/string.h>

#include "crypto.h"
#include "hex.h"
#include "json.h"
#include "tools/quote-check/row.h"

#define ROW_FIELDS	4

struct span {
	const char	*text;
	size_t		len;
};

/* What the line of one verdict holds, as json_walk() reports it. */
struct line {
	char	key[16];
	char	ak_public[BASE64_LEN(TPM_PUBLIC_MAX) + 1];
	int	objects;
	int	ok;
	bool	has_ok;
	bool	has_reason;
	bool	has_ak_public;
};

static bool row_fields(const __u8 *data, size_t size,
		       struct span fields[ROW_FIELDS])
{
	const char *row = (const char *)data;
	size_t start = 0, n = 0, i;

	for (i = 0; i <= size; i++) {
		if (i < size && row[i] != '\t')
			continue;
		if (n == ROW_FIELDS)
			return false;
		fields[n].text = row + start;
		fields[n].len = i - start;
		n++;
		start = i + 1;
	}
	return n == ROW_FIELDS;
}

static int base64_digit(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

/*
 * RFC 4648 section 4 without the decoder the checker uses: whole groups
 * of four digits, padding at the end alone, and zero in the bits of the
 * last digit that no byte takes.
 */
static bool is_canonical_base64(const struct span *field)
{
	size_t len = field->len, pad = 0, i;
	const char *s = field->text;

	if (len % 4)
		return false;
	while (pad < 2 && pad < len && s[len - 1 - pad] == '=')
		pad++;
	for (i = 0; i < len - pad; i++) {
		if (base64_digit(s[i]) < 0)
			return false;
	}
	if (pad == 1)
		return !(base64_digit(s[len - 2]) & 0x03);
	if (pad == 2)
		return !(base64_digit(s[len - 3]) & 0x0f);
	return true;
}

static bool is_sha256_hex(const struct span *field)
{
	size_t i;

	if (field->len != QUOTE_BODY_HEX_LEN)
		return false;
	for (i = 0; i < field->len; i++) {
		if (hex_nibble((__u8)field->text[i]) < 0)
			return false;
	}
	return true;
}

static int line_open(void *ctx, bool array)
{
	struct line *line = ctx;

	line->objects++;
	return array ? -EINVAL : 0;
}

static int line_key(void *ctx, const char *key)
{
	struct line *line = ctx;

	return strscpy(line->key, key, sizeof(line->key)) < 0 ? -E2BIG : 0;
}

static int line_string(void *ctx, const char *s)
{
	struct line *line = ctx;

	if (!strcmp(line->key, "reason")) {
		line->has_reason = true;
	} else if (!strcmp(line->key, "ak_public")) {
		line->has_ak_public = true;
		if (strscpy(line->ak_public, s, sizeof(line->ak_public)) < 0)
			return -E2BIG;
	}
	return 0;
}

static int line_number(void *ctx, const char *text, size_t len, bool integer)
{
	struct line *line = ctx;

	if (strcmp(line->key, "ok"))
		return 0;
	if (line->has_ok || len != 1 || (text[0] != '0' && text[0] != '1'))
		return -EINVAL;
	line->has_ok = true;
	line->ok = text[0] - '0';
	return 0;
}

static const struct json_visitor line_visitor = {
	.open	= line_open,
	.key	= line_key,
	.string	= line_string,
	.number	= line_number,
};

static bool same_result(const struct quote_result *a,
			const struct quote_result *b)
{
	return a->verdict == b->verdict &&
	       !memcmp(a->ak_name, b->ak_name, sizeof(a->ak_name)) &&
	       a->ak_public_len == b->ak_public_len &&
	       !memcmp(a->ak_public, b->ak_public, sizeof(a->ak_public)) &&
	       a->reset_count == b->reset_count && a->clock == b->clock;
}

/*
 * The line is one JSON object on one line within QUOTE_LINE_MAX, its
 * "ok" is the verdict, a reject alone names a reason, and an accepted
 * row's key comes back in the spelling the row gave it.
 */
static void check_line(const struct quote_result *res, const struct span *ak)
{
	bool accepted = res->verdict == QUOTE_OK;
	char text[QUOTE_LINE_MAX + 1];
	struct line line = {};
	size_t len;

	memset(text, 'x', sizeof(text));
	if (quote_row_emit(res, text, QUOTE_LINE_MAX))
		abort();
	len = strnlen(text, sizeof(text));
	if (len >= QUOTE_LINE_MAX || memchr(text, '\n', len) ||
	    json_walk(text, len, &line_visitor, &line) ||
	    line.objects != 1 || !line.has_ok || line.ok != accepted ||
	    line.has_reason == accepted || line.has_ak_public != accepted)
		abort();
	if (accepted &&
	    (strlen(line.ak_public) != ak->len ||
	     memcmp(line.ak_public, ak->text, ak->len)))
		abort();
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct span fields[ROW_FIELDS] = {};
	struct quote_result res, again;
	int ret;

	ret = quote_row_check((const char *)data, size, &res);
	if (quote_row_check((const char *)data, size, &again) != ret)
		abort();
	if (ret)
		return 0;
	if (!same_result(&res, &again))
		abort();

	switch (res.verdict) {
	case QUOTE_MALFORMED:
		break;
	case QUOTE_OK:
	case QUOTE_BAD_SIGNATURE:
	case QUOTE_BODY_MISMATCH:
		/* Nothing is checked of a row that is not all four fields. */
		if (!row_fields(data, size, fields) ||
		    !is_canonical_base64(&fields[0]) ||
		    !is_canonical_base64(&fields[1]) ||
		    !is_canonical_base64(&fields[2]) ||
		    !is_sha256_hex(&fields[3]) ||
		    res.ak_public_len > sizeof(res.ak_public))
			abort();
		break;
	default:
		abort();
	}
	check_line(&res, &fields[2]);
	return 0;
}
