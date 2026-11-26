// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * tree_event_replay() of util/bpm_tree_state.c is replayFrom of
 * testing/proofs/lean4/Shirudo/TreeSync.lean on every eventlog of LEN
 * lines: the root exactly when each line continues the chain, else an
 * error with nothing written. bpm-tree-state-replay-lines.c includes this
 * file for the bytes of the log. JSON, hex and SHA-256 are stubs.
 */

/* util/string.c is included behind a file that includes its header. */
#define STRING_INTERNAL

#include "proof.h"
#include "../../../util/bpm_tree_state.c"
/* lines_len() as the code has it; the file comes from the stub below. */
#define read_file read_file_unused
#include "../../../util/io.c"
#undef read_file
#include "../../../util/string.c"

#ifdef TREE_REPLAY_LINES
/* Each line is a byte and its newline at least. */
#define LOG_LEN		LEN
#define LINES_MAX	(LEN / 2 + 1)
#else
#define LOG_LEN		(2 * LEN)
#define LINES_MAX	(LEN + 1)
#endif

/* What json_parse() finds in a line: any fields, any values, or an error. */
struct record {
	int	ret;
	bool	seen[3];
	__s64	seq;
	char	digest[128];
	char	root[65];
};

static struct record records[LINES_MAX];
static size_t line_at[LINES_MAX], line_len[LINES_MAX];
static int n_lines;
static char original[LOG_LEN + 1], log_body[LOG_LEN + 1];
static int read_error, hash_error, n_freed;

/*
 * The log lies in a buffer of the harness, filled before anything can
 * fail: CBMC follows the bytes of a line as constants only when no
 * branch wrote them. xfree() below counts its release.
 */
static void any_log(void)
{
#ifdef TREE_REPLAY_LINES
	char any[LOG_LEN + 1];

	memcpy(log_body, any, sizeof(log_body));
#else
	/* A line of one byte each, which keeps the lines apart for CBMC. */
	for (int i = 0; i < LEN; i++) {
		log_body[2 * i] = 'x';
		log_body[2 * i + 1] = '\n';
	}
#endif
	log_body[LOG_LEN] = '\0';
	memcpy(original, log_body, LOG_LEN + 1);
}

/*
 * The log is handed out before the read can fail, so that CBMC knows
 * where it lies whatever the read returns; a failed read is checked to
 * parse and release nothing.
 */
int read_file(const char *path, size_t max, void *out, size_t *len)
{
	*(char **)out = log_body;
	*len = LOG_LEN;
	return read_error;
}

void xfree(void *ptr, size_t size)
{
	__CPROVER_assert(ptr == log_body && size == LOG_LEN + 1,
			 "the log released whole");
	n_freed++;
}

int json_parse(const char *data, size_t len, struct json_field *f, size_t n)
{
	const struct record *r;

	__CPROVER_assert(n_lines < LINES_MAX, "no more lines than the log has");
	__CPROVER_assert(n == 3 && f[0].type == JSON_T_INT &&
			 f[1].type == JSON_T_STRING && f[1].dst_cap == 128 &&
			 f[2].type == JSON_T_STRING && f[2].dst_cap == 65,
			 "a line's three fields, each with its room");
	__CPROVER_assert(len && data[len] == '\n', "a line is parsed whole");
	line_at[n_lines] = (size_t)(data - log_body);
	line_len[n_lines] = len;
	r = &records[n_lines++];
	if (r->seen[0])
		*(__s64 *)f[0].dst = r->seq;
	if (r->seen[1])
		memcpy(f[1].dst, r->digest, sizeof(r->digest));
	if (r->seen[2]) {
		/* The NUL as a constant ends CBMC's strlen() of the root. */
		memcpy(f[2].dst, r->root, sizeof(r->root));
		((char *)f[2].dst)[sizeof(r->root) - 1] = '\0';
	}
	for (int i = 0; i < 3; i++)
		f[i].seen = r->seen[i];
	return r->ret;
}

/*
 * util/hex.c has proofs of its own. Here 2 * n hex digits are any string
 * that does not start with '!', and decode to its first n bytes.
 */
int hex_decode(const char *hex, __u8 *out, size_t n)
{
	__CPROVER_assert(n == 32, "a SHA-256 digest");
	if (hex[0] == '!')
		return -EINVAL;
	for (size_t i = 0; i < n; i++)
		out[i] = (__u8)hex[i];
	return 0;
}

int sha256_digest_decode(const char *digest, __u8 out[32])
{
	return digest[0] == 's' ? hex_decode(digest + 7, out, 32) : -EINVAL;
}

/* SHA-256 as any function of 64 bytes that keeps their order apart. */
static void model_hash(const __u8 *in, __u8 out[32])
{
	for (int i = 0; i < 32; i++) {
		__u8 d = in[32 + i];

		out[i] = in[i] ^ (((d & 0x7f) << 1) | (d >> 7));
	}
}

int sha256_buffer(const void *data, size_t len, __u8 out[32])
{
	__CPROVER_assert(len == 64, "the root before and the digest");
	if (hash_error)
		return hash_error;
	model_hash(data, out);
	return 0;
}

static bool text_of_64(const char *s)
{
	bool whole = true;

	for (int i = 0; i < 64; i++)
		whole &= s[i] != '\0';
	return whole && !s[64];
}

/*
 * One step of replayFrom: the line is above seq and records the hash of
 * the chain and its digest, which the chain then is.
 */
static bool model_line(const struct record *r, __s64 *seq, __u8 chain[32])
{
	__u8 in[64], root[32], next[32];

	if (r->ret || !r->seen[0] || !r->seen[1] || !r->seen[2] ||
	    r->seq <= *seq || !text_of_64(r->root) ||
	    hex_decode(r->root, root, 32) ||
	    sha256_digest_decode(r->digest, in + 32))
		return false;
	memcpy(in, chain, 32);
	model_hash(in, next);
	if (memcmp(next, root, 32))
		return false;
	*seq = r->seq;
	memcpy(chain, next, 32);
	return true;
}

/*
 * The lines json_parse() saw are the whole lines of the log, in order:
 * each runs from the start of a line to its newline, and no byte before
 * the end of what was read, all of it without a refusal, is outside them
 * but a newline. The loops run to constants, which CBMC unwinds no
 * further.
 */
static void lines_whole(int ret)
{
	size_t whole = LOG_LEN, read_to = 0;

	while (whole && original[whole - 1] != '\n')
		whole--;
	for (int i = 0; i < LINES_MAX; i++) {
		size_t from = line_at[i], to = from + line_len[i];

		if (i >= n_lines)
			break;
		__CPROVER_assert(line_len[i] && to < whole && from >= read_to,
				 "a line with its newline, after the last one");
		__CPROVER_assert(original[to] == '\n' &&
				 (!from || original[from - 1] == '\n'),
				 "from the start of a line to its newline");
		read_to = to + 1;
	}
	for (size_t at = 0; at < LOG_LEN; at++) {
		bool in_line = false;

		for (int i = 0; i < LINES_MAX; i++)
			in_line |= i < n_lines && at >= line_at[i] &&
				   at < line_at[i] + line_len[i];
		__CPROVER_assert(!in_line || original[at] != '\n', "one line");
		__CPROVER_assert(in_line || original[at] == '\n' ||
				 at >= (ret ? read_to : whole),
				 "no line skipped");
	}
}

#ifdef TREE_REPLAY_LINES
/*
 * Records that replay, each a line above the one before with a digest
 * of its own, but for the one at bad, which json_parse() refuses.
 */
static void chained_records(int bad)
{
	__u8 in[64], chain[32] = {};

	for (int i = 0; i < LINES_MAX; i++) {
		struct record *r = &records[i];

		memcpy(in, chain, 32);
		memset(in + 32, 1 << i, 32);
		model_hash(in, chain);
		__CPROVER_assert(chain[0] && chain[0] != '!',
				 "a root the stubs decode");
		r->ret = i == bad ? -EINVAL : 0;
		r->seen[0] = true;
		r->seen[1] = true;
		r->seen[2] = true;
		r->seq = i + 1;
		memset(r->digest, 1 << i, 71);
		memcpy(r->digest, "sha256:", 7);
		memcpy(r->root, chain, 32);
		memset(r->root + 32, 'r', 32);
	}
}
#endif

void harness(void)
{
	__u8 out[32], was[32], chain[32] = {};
	int any_read_error, any_hash_error;
	bool nul = false, lines = true;
#ifdef TREE_REPLAY_LINES
	int bad;
#else
	struct record any_records[LINES_MAX];
#endif
	__s64 seq = 0;
	int ret;

	/* A global starts as zeros to CBMC, a local as anything. */
	read_error = any_read_error;
	hash_error = any_hash_error;
	__CPROVER_assume(read_error <= 0 && hash_error <= 0);
#ifdef TREE_REPLAY_LINES
	chained_records(bad);
#else
	memcpy(records, any_records, sizeof(records));
	for (int i = 0; i < LINES_MAX; i++)
		__CPROVER_assume(!records[i].digest[127] &&
				 !records[i].root[64] && records[i].ret <= 0);
#endif
	any_log();
	memcpy(was, out, 32);
	ret = tree_event_replay(out);
	__CPROVER_assert(n_freed == !read_error,
			 "the log released once, when it was read");
	if (read_error) {
		__CPROVER_assert(ret == read_error && !n_lines &&
				 !memcmp(out, was, 32),
				 "a log that cannot be read is its error");
		return;
	}
	for (int i = 0; i < LOG_LEN; i++)
		nul |= !original[i];
	if (nul) {
		__CPROVER_assert(ret == -EINVAL && !n_lines &&
				 !memcmp(out, was, 32),
				 "a log with a NUL is refused unread");
		return;
	}
	lines_whole(ret);
	for (int i = 0; i < LINES_MAX; i++) {
		bool line;

		if (i >= n_lines)
			break;
		line = !hash_error && model_line(&records[i], &seq, chain);
		__CPROVER_assert(line || i == n_lines - 1,
				 "nothing read after a line that is refused");
		lines &= line;
	}
	__CPROVER_assert(!ret == lines, "replayFrom of the model");
	if (ret)
		__CPROVER_assert((ret == -EINVAL || ret == hash_error) &&
				 !memcmp(out, was, 32),
				 "a refusal writes no root");
	else
		__CPROVER_assert(!memcmp(out, chain, 32),
				 "the root of the last line, or 32 zeros");
}
