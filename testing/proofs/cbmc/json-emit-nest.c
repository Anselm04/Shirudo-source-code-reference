// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The containers of util/json.c: every sequence of up to CALLS calls that
 * json.h allows, closed at the end, writes one JSON text of ECMA-404, and
 * at every depth the emitter has, a container takes its commas and leaves
 * those of the others as they were.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/json.c"

#define CALLS	4
#define OUT_MAX	56

enum state { VALUE, FIRST_VALUE, KEY, FIRST_KEY, COLON, NEXT, STRING,
	     ESCAPE, HEX, SIGN, ZERO, DIGITS, WORD };

static bool hex_digit(__u8 c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
	       (c >= 'A' && c <= 'F');
}

static bool close_ok(char c, bool *array, size_t *depth, enum state *s)
{
	if (!*depth || c != (array[*depth - 1] ? ']' : '}'))
		return false;
	--*depth;
	*s = NEXT;
	return true;
}

/*
 * ECMA-404 as a pushdown automaton over bytes, for text without white
 * space, numbers with no fraction or exponent and ASCII strings: a subset
 * of the grammar, so what it takes is JSON.
 */
static bool json_text(const char *t, size_t n)
{
	static const char escapes[] = "\"\\/bfnrt";
	bool array[CALLS + 1], key = false;
	size_t i, depth = 0, hex = 0;
	const char *word = "";
	enum state s = VALUE;
	__u8 c;

	for (i = 0; i < n; i++) {
		c = t[i];
		switch (s) {
		case STRING:
			if (c == '"')
				s = key ? COLON : NEXT;
			else if (c == '\\')
				s = ESCAPE;
			else if (c < 0x20 || c >= 0x80)
				return false;
			continue;
		case ESCAPE:
			if (c == 'u') {
				s = HEX;
				hex = 0;
			} else if (memchr(escapes, c, sizeof(escapes) - 1)) {
				s = STRING;
			} else {
				return false;
			}
			continue;
		case HEX:
			if (!hex_digit(c))
				return false;
			if (++hex == 4)
				s = STRING;
			continue;
		case SIGN:
			if (c < '0' || c > '9')
				return false;
			s = c == '0' ? ZERO : DIGITS;
			continue;
		case DIGITS:
			if (c >= '0' && c <= '9')
				continue;
			s = NEXT;
			break;
		case ZERO:
			s = NEXT;
			break;
		case WORD:
			if (c != *word++)
				return false;
			if (!*word)
				s = NEXT;
			continue;
		case COLON:
			if (c != ':')
				return false;
			s = VALUE;
			continue;
		default:
			break;
		}
		if (s == NEXT) {
			if (c == ',' && depth) {
				s = array[depth - 1] ? VALUE : KEY;
				continue;
			}
			if (!close_ok(c, array, &depth, &s))
				return false;
			continue;
		}
		if ((s == FIRST_VALUE && c == ']') || (s == FIRST_KEY && c == '}')) {
			close_ok(c, array, &depth, &s);
			continue;
		}
		key = s == KEY || s == FIRST_KEY;
		if (key && c != '"')
			return false;
		if (c == '{' || c == '[') {
			if (depth == CALLS + 1)
				return false;
			array[depth++] = c == '[';
			s = c == '[' ? FIRST_VALUE : FIRST_KEY;
		} else if (c == '"') {
			s = STRING;
		} else if (c == '-') {
			s = SIGN;
		} else if (c >= '0' && c <= '9') {
			s = c == '0' ? ZERO : DIGITS;
		} else {
			word = c == 't' ? "rue" : c == 'f' ? "alse" :
			       c == 'n' ? "ull" : NULL;
			if (!word)
				return false;
			s = WORD;
		}
	}
	return !depth && s == NEXT;
}

static void push(bool *array, size_t *depth, bool is_array)
{
	array[(*depth)++] = is_array;
}

static void value(struct json_emit *e, __u8 op, bool *array, size_t *depth)
{
	switch (op % 6) {
	case 0:
		json_obj_value_open(e);
		push(array, depth, false);
		return;
	case 1:
		json_arr_open_value(e);
		push(array, depth, true);
		return;
	case 2:
		json_str_value(e, "v");
		return;
	case 3:
		json_raw_value(e, "-1", 2);
		return;
	case 4:
		json_u64_value(e, 42);
		return;
	}
	json_str_lossy(e, "\xff", 1);
}

static void element(struct json_emit *e, __u8 op, bool *array,
		    size_t *depth)
{
	switch (op % 4) {
	case 0:
		json_str(e, "w");
		return;
	case 1:
		json_raw(e, "true", 4);
		return;
	case 2:
		json_obj_open(e);
		push(array, depth, false);
		return;
	}
	value(e, op / 4, array, depth);
}

static void member(struct json_emit *e, __u8 op, bool *array, size_t *depth,
		   bool *pending)
{
	switch (op % 11) {
	case 0:
		json_obj_open_key(e, "o");
		push(array, depth, false);
		return;
	case 1:
		json_arr_open(e, "a");
		push(array, depth, true);
		return;
	case 2:
		json_key(e, "k");
		*pending = true;
		return;
	case 3:
		json_key_lossy(e, "\x01", 1);
		*pending = true;
		return;
	case 4:
		json_kv_string(e, "s", "\"");
		return;
	case 5:
		json_kv_int(e, "i", -7);
		return;
	case 6:
		json_kv_bool(e, "b", op & 16);
		return;
	case 7:
		json_kv_null(e, "n");
		return;
	case 8:
		json_kv_u64(e, "u", 42);
		return;
	case 9:
		json_kv_string_lossy(e, "l", "\xff");
		return;
	}
	json_kv_raw(e, "r", "[]", 2);
}

static void close_container(struct json_emit *e, bool *array,
			    size_t *depth)
{
	if (array[--*depth])
		json_arr_close(e);
	else
		json_obj_close(e);
}

/* One call json.h allows where the emitter stands, as op picks it. */
static void step(struct json_emit *e, __u8 op, bool *array, size_t *depth,
		 bool *pending)
{
	if (*pending) {
		*pending = false;
		value(e, op, array, depth);
	} else if (op % 8 == 7) {
		close_container(e, array, depth);
	} else if (array[*depth - 1]) {
		element(e, op / 8, array, depth);
	} else {
		member(e, op / 8, array, depth, pending);
	}
}

static void sequences(void)
{
	bool array[CALLS + 1], pending = false, root;
	struct json_emit e = {};
	size_t depth = 0, i;

	e.buf = any_bytes(OUT_MAX);
	e.cap = OUT_MAX;
	if (root)
		json_arr_open_value(&e);
	else
		json_obj_open(&e);
	push(array, &depth, root);
	for (i = 0; i < CALLS - 1 && depth; i++) {
		bool more;
		__u8 op;

		if (!more)
			break;
		step(&e, op, array, &depth, &pending);
	}
	if (pending)
		json_str_value(&e, "x");
	while (depth)
		close_container(&e, array, &depth);
	__CPROVER_assert(!e.err, "room enough");
	__CPROVER_assert(json_text(e.buf, e.len), "one JSON text");
}

/* A container at depth d, which a member before it may precede. */
static void any_depth(void)
{
	__u64 was[JSON_EMIT_MAX_DEPTH / 64];
	struct json_emit e = {};
	char out[16];
	__u32 d, w;
	bool had;

	__CPROVER_assume(d < JSON_EMIT_MAX_DEPTH);
	for (w = 0; w < ARRAY_SIZE(was); w++)
		e.nonempty[w] = was[w];
	e.buf = out;
	e.cap = sizeof(out);
	e.depth = d;
	had = was[d / 64] >> (d % 64) & 1;
	json_arr_open_value(&e);
	if (d + 1 == JSON_EMIT_MAX_DEPTH) {
		__CPROVER_assert(e.err == -E2BIG, "no deeper than the bitmap");
		return;
	}
	json_str_value(&e, "a");
	json_str_value(&e, "b");
	json_arr_close(&e);
	__CPROVER_assert(!e.err && e.depth == d, "back at depth d");
	__CPROVER_assert(!strcmp(out, ",[\"a\",\"b\"]" + !had),
			 "a comma after a member alone");
	for (w = 0; w < ARRAY_SIZE(was); w++)
		__CPROVER_assert(e.nonempty[w] == (was[w] |
			(w == d / 64 ? 1ull << d % 64 : 0) |
			(w == (d + 1) / 64 ? 1ull << (d + 1) % 64 : 0)),
			"the bits of the other depths kept");
}

void harness(void)
{
	sequences();
	any_depth();
}
