// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * keepalive_emit() of util/keepalive.c: three bodies, each one JSON
 * object of 23 members; a last number of up to LEN + 1 digits in a room
 * for LEN changes only its digits, or is -ENOSPC exactly when too long;
 * a bad input, a room cut short or a string not UTF-8 leaves no body.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/json.c"
#include "../../../util/keepalive.c"

#define HASH \
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define NOT_A_HASH	"sha256:0123456789abcdef"
#define MEMBERS		23
/* Past the longest of these bodies, and a room inside the shortest. */
#define ROOM		960
#define CUT_SHORT	(ROOM / 4)

enum state { START, KEY, STRING, COLON, VALUE, ELEMENT, ZERO, DIGITS, WORD,
	     NEXT, END };

/* Counters of the widest value, of two digits and of one. */
static const __u64 counters[TAMPER_MAX] = { UINT64_MAX, 10 };
static const __u64 integrity[INTEGRITY_MAX] = { UINT64_MAX };
static char reference[ROOM];

/* keepalive_mask() is not reached: the mask comes in as text. */
int base64_encode(const __u8 *data, size_t len, char *out, size_t out_sz)
{
	__CPROVER_assert(false, "no base64 in the emitter");
	return -EINVAL;
}

static bool number_start(__u8 c, enum state *s)
{
	if (c < '0' || c > '9')
		return false;
	*s = c == '0' ? ZERO : DIGITS;
	return true;
}

/*
 * The members of one object of ECMA-404 without white space, whose values
 * are ASCII strings without escapes, null, unsigned integers and arrays
 * of those integers: a subset of the grammar, so what it takes is JSON.
 * -1 for any other text.
 */
static int json_members(const char *t, size_t n)
{
	bool key = false, array = false;
	enum state s = START;
	size_t i, word = 0;
	int members = 1;
	__u8 c;

	for (i = 0; i < n; i++) {
		c = t[i];
		switch (s) {
		case START:
			if (c != '{')
				return -1;
			s = KEY;
			continue;
		case KEY:
			if (c != '"')
				return -1;
			key = true;
			s = STRING;
			continue;
		case STRING:
			if (c == '"')
				s = key ? COLON : NEXT;
			else if (c < 0x20 || c == '\\' || c >= 0x80)
				return -1;
			continue;
		case COLON:
			if (c != ':')
				return -1;
			key = false;
			s = VALUE;
			continue;
		case WORD:
			if (c != "null"[word++])
				return -1;
			if (word == 4)
				s = NEXT;
			continue;
		case VALUE:
			if (c == '"') {
				s = STRING;
			} else if (c == 'n') {
				word = 1;
				s = WORD;
			} else if (c == '[') {
				array = true;
				s = ELEMENT;
			} else if (!number_start(c, &s)) {
				return -1;
			}
			continue;
		case ELEMENT:
			if (!number_start(c, &s))
				return -1;
			continue;
		case DIGITS:
			if (c >= '0' && c <= '9')
				continue;
			break;
		case END:
			return -1;
		default:
			break;
		}
		if (c == ',') {
			s = array ? ELEMENT : KEY;
			members += !array;
		} else if (c == ']' && array) {
			array = false;
			s = NEXT;
		} else if (c == '}' && !array) {
			s = END;
		} else {
			return -1;
		}
	}
	return s == END ? members : -1;
}

static struct keepalive_input without_a_tree(void)
{
	return (struct keepalive_input){
		.boot_id = "b",
		.version_id = HASH,
		.kernel_release = "k",
		.verdict = "init-pending",
		.flags = 8,
		.set_sha256 = HASH,
	};
}

static struct keepalive_input with_a_tree_alone(void)
{
	struct keepalive_input in = without_a_tree();

	in.config_root = "";
	in.image_id = "";
	in.tree = true;
	in.tree_id = "t";
	in.base_root = "";
	in.projection_root = HASH;
	in.mask = "";
	return in;
}

static struct keepalive_input with_every_value(void)
{
	return (struct keepalive_input){
		.boot_id = "b",
		.version_id = HASH,
		.config_root = HASH,
		.kernel_release = "k",
		.image_id = "i",
		.image_version = "v",
		.image_root = HASH,
		.verdict = "ok",
		.cond = 5461,
		.flags = 127,
		.tamper = counters,
		.integrity = integrity,
		.tree = true,
		.tree_id = "t",
		.generation = 42,
		.last_seq = 12,
		.base_root = HASH,
		.projection_root = HASH,
		.mask = "WdlZAA==",
		.set_sha256 = HASH,
		.count = 7,
	};
}

static __u64 power_of_ten(size_t digits)
{
	__u64 power = 1;
	size_t i;

	for (i = 0; i < digits; i++)
		power *= 10;
	return power;
}

/*
 * Each byte of these bodies is a constant: past a symbolic one the
 * recognizer would branch at every byte to the end of its room.
 */
static void is_an_object(const struct keepalive_input *in)
{
	char *buf = any_bytes(ROOM);
	size_t len;

	__CPROVER_assert(!keepalive_emit(in, buf, ROOM, &len) && len < ROOM &&
			 !buf[len], "the body fits, terminated");
	__CPROVER_assert(json_members(buf, len) == MEMBERS,
			 "one JSON object of 23 members");
}

/*
 * The body whose last number is 0, an object as is_an_object() shows, is
 * the reference: with any other number only the digits before its close
 * differ, and they are that number's, so that the body stays an object.
 * The room ends the buffer, so that a write past it fails the proof.
 */
static void ends_in_any_number(struct keepalive_input in)
{
	size_t prefix, cap, len, digits, i;
	__u64 number, value = 0;
	char *buf;
	int ret;

	in.not_ok = 0;
	__CPROVER_assert(!keepalive_emit(&in, reference, ROOM, &len),
			 "the reference fits");
	prefix = len - 2;
	cap = len + LEN;
	__CPROVER_assume(number < power_of_ten(LEN + 1));
	for (digits = 1; number >= power_of_ten(digits); digits++)
		;
	in.not_ok = number;
	buf = any_bytes(cap);
	ret = keepalive_emit(&in, buf, cap, &len);
	__CPROVER_assert((ret == -ENOSPC) == (digits > LEN),
			 "-ENOSPC exactly for a number too long");
	if (ret) {
		__CPROVER_assert(ret == -ENOSPC && !len && !buf[0],
				 "a refusal leaves no body");
		return;
	}
	__CPROVER_assert(len == prefix + digits + 1 && buf[len - 1] == '}' &&
			 !buf[len], "the digits, the close, the terminator");
	for (i = 0; i < prefix; i++)
		__CPROVER_assert(buf[i] == reference[i],
				 "the body before the number unchanged");
	__CPROVER_assert(digits == 1 || buf[prefix] != '0', "no leading zero");
	for (i = prefix; i < prefix + digits; i++) {
		__CPROVER_assert(buf[i] >= '0' && buf[i] <= '9',
				 "decimal digits");
		value = value * 10 + (__u64)(buf[i] - '0');
	}
	__CPROVER_assert(value == number, "the number's own digits");
}

static void refuses(const struct keepalive_input *in, size_t cap, int want)
{
	char *buf = cap ? any_bytes(cap) : NULL;
	size_t len;
	int ret;

	ret = keepalive_emit(in, buf, cap, &len);
	__CPROVER_assert(ret == want,
			 "-ENOSPC for the room, else for the input");
	__CPROVER_assert(!len && (!cap || !buf[0]), "a refusal leaves no body");
}

void harness(void)
{
	struct keepalive_input in = without_a_tree();

	ends_in_any_number(with_every_value());
	if (LEN)
		return;
	refuses(&in, 0, -ENOSPC);
	refuses(&in, 1, -ENOSPC);
	refuses(&in, CUT_SHORT, -ENOSPC);
	in.kernel_release = "\xff";
	refuses(&in, ROOM, -EILSEQ);
	in.boot_id = NULL;
	refuses(&in, ROOM, -EINVAL);
	in = with_a_tree_alone();
	in.projection_root = NOT_A_HASH;
	refuses(&in, ROOM, -EINVAL);

	in = without_a_tree();
	is_an_object(&in);
	in = with_a_tree_alone();
	is_an_object(&in);
	in = with_every_value();
	is_an_object(&in);
}
