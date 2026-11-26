// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_semver_compare() of util/bpm_package.c against the model that
 * testing/proofs/lean4/Shirudo/SemVer.lean proves a total order: on every
 * pair of strings of up to LEN bytes it returns the sign the model gives.
 * The functions below restate the Lean definitions: break_at() is breakAt,
 * split_on() and next_ident() splitOn, the others are named after theirs.
 */

/* As proof.h, before the OpenSSL headers can include <ctype.h>. */
#define __NO_CTYPE 1

#include <stdbool.h>
#include <zlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "proof.h"
#include "../../../util/string.c"
#include "../../../util/bpm_package.c"

/* No value of LEN digits reaches 2^64, so numeral() needs no limit. */
_Static_assert(LEN < 20, "LEN digits stay below 2^64");

struct span {
	const char	*s;
	size_t		off;
	size_t		len;
};

struct version {
	bool		valid;
	__u64		core[3];
	bool		has_pre;
	struct span	pre;
	struct span	bytes;
};

static char at(struct span x, size_t i)
{
	return x.s[x.off + i];
}

static struct span sub(struct span x, size_t off, size_t len)
{
	return (struct span){ x.s, x.off + off, len };
}

static int cmp_nat(__u64 x, __u64 y)
{
	return x == y ? 0 : x > y ? 1 : -1;
}

static bool is_digit(char b)
{
	return b >= '0' && b <= '9';
}

static bool ident_byte(char b)
{
	return is_digit(b) || (b >= 'A' && b <= 'Z') ||
	       (b >= 'a' && b <= 'z') || b == '-';
}

static bool numeric(struct span id)
{
	for (size_t i = 0; i < id.len; i++) {
		if (!is_digit(at(id, i)))
			return false;
	}
	return true;
}

static bool leading_zero(struct span id)
{
	return id.len > 1 && at(id, 0) == '0';
}

static bool break_at(struct span x, char sep, struct span *before,
		     struct span *after)
{
	size_t i = 0;

	while (i < x.len && at(x, i) != sep)
		i++;
	*before = sub(x, 0, i);
	*after = i < x.len ? sub(x, i + 1, x.len - i - 1) : sub(x, i, 0);
	return i < x.len;
}

static bool split_on(struct span x, struct span *piece, struct span *rest)
{
	size_t i = 0;

	while (i < x.len && at(x, i) != '.')
		i++;
	*piece = sub(x, 0, i);
	*rest = i < x.len ? sub(x, i + 1, x.len - i - 1) : sub(x, i, 0);
	return i < x.len;
}

/*
 * split_on() over a list of identifiers, apart from it so that its loop
 * takes the bound of a prerelease rather than of a whole version.
 */
static bool next_ident(struct span x, struct span *id, struct span *rest)
{
	size_t i = 0;

	while (i < x.len && at(x, i) != '.')
		i++;
	*id = sub(x, 0, i);
	*rest = i < x.len ? sub(x, i + 1, x.len - i - 1) : sub(x, i, 0);
	return i < x.len;
}

static bool split_three(struct span x, struct span *p0, struct span *p1,
			struct span *p2)
{
	struct span rest;

	return split_on(x, p0, &rest) && split_on(rest, p1, p2) &&
	       !split_on(*p2, p2, &rest);
}

static bool numeral(struct span id, __u64 *v)
{
	if (!id.len || !numeric(id) || leading_zero(id))
		return false;
	*v = 0;
	for (size_t i = 0; i < id.len; i++)
		*v = *v * 10 + (__u64)(at(id, i) - '0');
	return true;
}

static bool ident_ok(bool pre, struct span id)
{
	for (size_t i = 0; i < id.len; i++) {
		if (!ident_byte(at(id, i)))
			return false;
	}
	return id.len && !(pre && numeric(id) && leading_zero(id));
}

static bool identifiers(bool pre, struct span x)
{
	struct span id;
	bool more = true;

	while (more) {
		more = next_ident(x, &id, &x);
		if (!ident_ok(pre, id))
			return false;
	}
	return true;
}

static void semver_model_parse(struct span x, struct version *v)
{
	struct span head, build, core, p0, p1, p2;
	bool has_build;

	v->bytes = x;
	has_build = break_at(x, '+', &head, &build);
	v->has_pre = break_at(head, '-', &core, &v->pre);
	v->valid = split_three(core, &p0, &p1, &p2) &&
		   numeral(p0, &v->core[0]) && numeral(p1, &v->core[1]) &&
		   numeral(p2, &v->core[2]) &&
		   (!v->has_pre || identifiers(true, v->pre)) &&
		   (!has_build || identifiers(false, build));
}

static int lex_bytes(struct span a, struct span b)
{
	size_t i;

	for (i = 0; i < a.len && i < b.len; i++) {
		if (at(a, i) != at(b, i))
			return cmp_nat((__u8)at(a, i), (__u8)at(b, i));
	}
	return i < a.len ? 1 : i < b.len ? -1 : 0;
}

static int memcmp_model(struct span a, struct span b)
{
	for (size_t i = 0; i < a.len && i < b.len; i++) {
		if (at(a, i) != at(b, i))
			return cmp_nat((__u8)at(a, i), (__u8)at(b, i));
	}
	return 0;
}

static int alnum_cmp(struct span a, struct span b)
{
	int c = memcmp_model(a, b);

	return c ? c : cmp_nat(a.len, b.len);
}

static int num_cmp(struct span a, struct span b)
{
	if (a.len != b.len)
		return a.len > b.len ? 1 : -1;
	return memcmp_model(a, b);
}

static int ident_cmp(struct span a, struct span b)
{
	bool na = numeric(a), nb = numeric(b);

	if (na && nb)
		return num_cmp(a, b);
	if (na != nb)
		return na ? -1 : 1;
	return alnum_cmp(a, b);
}

static int lex_idents(struct span a, struct span b)
{
	bool more_a = true, more_b = true;
	struct span ia, ib;
	int c;

	while (more_a && more_b) {
		more_a = next_ident(a, &ia, &a);
		more_b = next_ident(b, &ib, &b);
		c = ident_cmp(ia, ib);
		if (c)
			return c;
	}
	return more_a ? 1 : more_b ? -1 : 0;
}

static int pre_cmp(const struct version *a, const struct version *b)
{
	if (!a->has_pre || !b->has_pre)
		return a->has_pre ? -1 : b->has_pre ? 1 : 0;
	return lex_idents(a->pre, b->pre);
}

static int semver_model_compare(const struct version *a,
				const struct version *b)
{
	int c;

	if (!a->valid && !b->valid)
		return lex_bytes(a->bytes, b->bytes);
	if (!a->valid || !b->valid)
		return a->valid ? 1 : -1;
	for (int i = 0; i < 3; i++) {
		c = cmp_nat(a->core[i], b->core[i]);
		if (c)
			return c;
	}
	return pre_cmp(a, b);
}

/* A string of up to LEN bytes, with nothing but NULs after its end. */
static char *any_string(void)
{
	char *s = any_bytes(LEN + 1);

	for (int i = 0; i < LEN; i++)
		__CPROVER_assume(s[i] || !s[i + 1]);
	s[LEN] = '\0';
	return s;
}

void harness(void)
{
	char *a = any_string(), *b = any_string();
	struct version va, vb;

	semver_model_parse((struct span){ a, 0, strnlen(a, LEN) }, &va);
	semver_model_parse((struct span){ b, 0, strnlen(b, LEN) }, &vb);
	__CPROVER_assert(bpm_semver_compare(a, b) ==
			 semver_model_compare(&va, &vb),
			 "the sign of the model's order");
}
