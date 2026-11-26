/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The models of testing/proofs/lean4/Shirudo/JsonString.lean in C, a
 * branch of the model a turn, for the harnesses that check util/json.c
 * against them: the strict writer, write, and the reader, readString.
 */

#ifndef SHIRUDO_PROOF_JSON_MODEL_H
#define SHIRUDO_PROOF_JSON_MODEL_H

static const char model_table[] = "0123456789abcdef";

static bool in(__u32 c, __u32 lo, __u32 hi)
{
	return c >= lo && c <= hi;
}

/* rowWidth, Row1 to Row4 of Table 3-7, on the n bytes at s. */
static size_t model_width(const __u8 *s, size_t n)
{
	if (n >= 1 && s[0] <= 0x7f)
		return 1;
	if (n >= 2 && in(s[0], 0xc2, 0xdf) && in(s[1], 0x80, 0xbf))
		return 2;
	if (n >= 3 && in(s[2], 0x80, 0xbf) &&
	    ((s[0] == 0xe0 && in(s[1], 0xa0, 0xbf)) ||
	     (in(s[0], 0xe1, 0xec) && in(s[1], 0x80, 0xbf)) ||
	     (s[0] == 0xed && in(s[1], 0x80, 0x9f)) ||
	     (in(s[0], 0xee, 0xef) && in(s[1], 0x80, 0xbf))))
		return 3;
	if (n >= 4 && in(s[2], 0x80, 0xbf) && in(s[3], 0x80, 0xbf) &&
	    ((s[0] == 0xf0 && in(s[1], 0x90, 0xbf)) ||
	     (in(s[0], 0xf1, 0xf3) && in(s[1], 0x80, 0xbf)) ||
	     (s[0] == 0xf4 && in(s[1], 0x80, 0x8f))))
		return 4;
	return 0;
}

/* writeBody between write's quotes, one branch of the model a byte. */
static int model_write(const __u8 *s, size_t len, __u8 *out, size_t *n)
{
	size_t i = 0, k = 0, w;

	out[k++] = '"';
	while (i < len) {
		__u8 c = s[i];

		if (c == '"' || c == '\\') {
			out[k++] = '\\';
			out[k++] = c;
			i++;
		} else if (c == 0x0a || c == 0x0d || c == 0x09) {
			out[k++] = '\\';
			out[k++] = c == 0x0a ? 'n' : c == 0x0d ? 'r' : 't';
			i++;
		} else if (c && c < 0x20) {
			out[k++] = '\\';
			out[k++] = 'u';
			out[k++] = model_table[c / 4096 % 16];
			out[k++] = model_table[c / 256 % 16];
			out[k++] = model_table[c / 16 % 16];
			out[k++] = model_table[c % 16];
			i++;
		} else if (c && c < 0x80) {
			out[k++] = c;
			i++;
		} else {
			w = c ? model_width(s + i, min(len - i, 4U)) : 0;
			if (!w)
				return -EILSEQ;
			while (w--)
				out[k++] = s[i++];
		}
	}
	out[k++] = '"';
	*n = k;
	return 0;
}

/* Room: dst given, its cap, and JSON_MAX_STRING_BYTES. */
struct room {
	bool	dst;
	size_t	cap;
	size_t	max;
};

/* emit. */
static int model_emit(const struct room *r, __u8 *out, size_t *k, __u32 b)
{
	if (*k >= r->max)
		return -E2BIG;
	if (r->dst && *k + 1 >= r->cap)
		return -ENOSPC;
	out[(*k)++] = (__u8)b;
	return 0;
}

/* emitAll. */
static int model_emit_all(const struct room *r, __u8 *out, size_t *k,
			  const __u32 *b, size_t n)
{
	size_t i;
	int ret;

	for (i = 0; i < n; i++) {
		ret = model_emit(r, out, k, b[i]);
		if (ret)
			return ret;
	}
	return 0;
}

/* emitCp, with utf8Emit below U+10000 and utf8Four from it. */
static int model_emit_cp(const struct room *r, __u8 *out, size_t *k,
			 __u32 cp)
{
	__u32 b[4];

	if (cp < 0x80)
		return model_emit(r, out, k, cp);
	if (cp < 0x800) {
		b[0] = 0xc0 | (cp >> 6);
		b[1] = 0x80 | (cp & 0x3f);
		return model_emit_all(r, out, k, b, 2);
	}
	if (cp < 0x10000) {
		b[0] = 0xe0 | (cp >> 12);
		b[1] = 0x80 | ((cp >> 6) & 0x3f);
		b[2] = 0x80 | (cp & 0x3f);
		return model_emit_all(r, out, k, b, 3);
	}
	b[0] = 0xf0 | (cp >> 18);
	b[1] = 0x80 | ((cp >> 12) & 0x3f);
	b[2] = 0x80 | ((cp >> 6) & 0x3f);
	b[3] = 0x80 | (cp & 0x3f);
	return model_emit_all(r, out, k, b, 4);
}

/* Hex.nibble, -1 for none. */
static int model_nibble(__u8 c)
{
	if (c >= 0x30 && c <= 0x39)
		return c - 0x30;
	if (c >= 0x61 && c <= 0x66)
		return c - 0x61 + 10;
	if (c >= 0x41 && c <= 0x46)
		return c - 0x41 + 10;
	return -1;
}

/* hex4, -1 for none. */
static int model_hex4(const __u8 *d)
{
	int v = 0, n, i;

	for (i = 0; i < 4; i++) {
		n = model_nibble(d[i]);
		if (n < 0)
			return -1;
		v = v * 16 + n;
	}
	return v;
}

/* simpleEscape, -1 for none. */
static int model_simple_escape(__u8 e)
{
	if (e == 0x22 || e == 0x5c || e == 0x2f)
		return e;
	if (e == 0x62)
		return 0x08;
	if (e == 0x66)
		return 0x0c;
	if (e == 0x6e)
		return 0x0a;
	if (e == 0x72)
		return 0x0d;
	if (e == 0x74)
		return 0x09;
	return -1;
}

/* uCodePoint on the bytes from t[*i] to t[n], moving *i past them. */
static int model_code_point(const __u8 *t, size_t n, size_t *i, __u32 *cp)
{
	int hi, lo;

	if (n - *i < 4)
		return -EINVAL;
	hi = model_hex4(t + *i);
	if (hi < 0 || !hi)
		return -EINVAL;
	*i += 4;
	if (in(hi, 0xd800, 0xdbff)) {
		if (n - *i < 6 || t[*i] != '\\' || t[*i + 1] != 'u')
			return -EINVAL;
		lo = model_hex4(t + *i + 2);
		if (lo < 0 || !in(lo, 0xdc00, 0xdfff))
			return -EINVAL;
		*i += 6;
		*cp = 0x10000 + (hi - 0xd800) * 1024 + (lo - 0xdc00);
		return 0;
	}
	if (in(hi, 0xdc00, 0xdfff))
		return -EINVAL;
	*cp = hi;
	return 0;
}

/* readString and readLoop, one branch of the model a turn. */
static int model_read(const __u8 *t, size_t n, const struct room *r,
		      __u8 *out, size_t *k, size_t *end)
{
	__u32 b[4], cp;
	size_t i = 0, w, j;
	int ret, v;
	__u8 ch;

	if (i == n || t[i] != '"')
		return -EINVAL;
	i++;
	for (;;) {
		if (i == n)
			return -EINVAL;
		ch = t[i];
		if (ch == '"') {
			i++;
			break;
		}
		if (ch == '\\') {
			if (i + 1 == n)
				return -EINVAL;
			v = model_simple_escape(t[i + 1]);
			i += 2;
			if (v >= 0) {
				ret = model_emit(r, out, k, v);
				if (ret)
					return ret;
				continue;
			}
			if (t[i - 1] != 'u')
				return -EINVAL;
			ret = model_code_point(t, n, &i, &cp);
			if (!ret)
				ret = model_emit_cp(r, out, k, cp);
			if (ret)
				return ret;
			continue;
		}
		if (ch < 0x20)
			return -EINVAL;
		w = model_width(t + i, n - i);
		if (!w)
			return -EINVAL;
		for (j = 0; j < w; j++)
			b[j] = t[i + j];
		ret = model_emit_all(r, out, k, b, w);
		if (ret)
			return ret;
		i += w;
	}
	if (r->dst && !r->cap)
		return -ENOSPC;
	*end = i;
	return 0;
}

#endif /* SHIRUDO_PROOF_JSON_MODEL_H */
