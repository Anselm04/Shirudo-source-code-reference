// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * pending.json of util/bpm_tree_state.c: tree_pending_parse() takes exactly
 * a whole record of schema 1, and what tree_pending_write() writes of an
 * operation reads back as that operation. util/json.c is a stub that hands
 * keys and values over; json-roundtrip and json-field prove its bytes.
 */

/* util/string.c behind a file that includes its header. */
#define STRING_INTERNAL

/* CBMC's own memcpy() of a length it does not know runs out of memory. */
#define PROOF_MEMCPY_BYTEWISE

#include "proof.h"
#include "../../../util/bpm_tree_state.c"
#include "../../../util/hex.c"
#include "../../../util/string.c"
#include "../../../util/upatch.c"

#define ID_MAX		8

/* What the emitter was given: a key and a number or a string. */
struct member {
	const char	*key;
	bool		number;
	__s64		value;
	const char	*text;
};

#define MEMBERS_MAX	4

static struct member members[MEMBERS_MAX];
static int n_members, n_written;
static bool opened, closed, reading_back;
static int emit_error, mkdir_error, write_error, read_back_ret;
static struct tree_pending read_back;
static const char *emitted;
static size_t emitted_len;

/* What json_parse() finds in a document that was not written here. */
struct found {
	int	ret;
	bool	seen[4];
	__s64	schema;
	__s64	seq;
	char	id[TREE_STRING_MAX];
	char	digest[128];
};

static struct found found;

void json_obj_open(struct json_emit *e)
{
	__CPROVER_assert(!opened && !n_members, "one object");
	opened = true;
}

void json_kv_int(struct json_emit *e, const char *key, __s64 val)
{
	__CPROVER_assert(opened && !closed && n_members < MEMBERS_MAX,
			 "a member of the open object");
	members[n_members++] = (struct member){ key, true, val, NULL };
}

void json_kv_string(struct json_emit *e, const char *key, const char *val)
{
	__CPROVER_assert(opened && !closed && n_members < MEMBERS_MAX,
			 "a member of the open object");
	members[n_members++] = (struct member){ key, false, 0, val };
}

void json_obj_close(struct json_emit *e)
{
	size_t len;

	__CPROVER_assert(opened && !closed, "the object closed once");
	__CPROVER_assume(len <= e->cap);
	closed = true;
	e->len = len;
	e->err = emit_error;
	emitted = e->buf;
	emitted_len = len;
}

int seal_mkdir_p(const char *path, mode_t mode)
{
	__CPROVER_assert(!n_written, "the directory before the file");
	return mkdir_error;
}

/* The record is read back while the buffer that holds it is there. */
int seal_write_file(const char *path, const void *data, size_t len,
		    mode_t mode)
{
	__CPROVER_assert(closed && !emit_error && data == emitted &&
			 len == emitted_len,
			 "the whole document, when the emitter took it");
	n_written++;
	reading_back = true;
	read_back_ret = tree_pending_parse(data, len, &read_back);
	reading_back = false;
	return write_error;
}

/* The members that name a field, each once, of its type and fitting. */
static int members_read(struct json_field *f, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		for (int j = 0; j < n_members; j++) {
			const struct member *m = &members[j];
			bool number = f[i].type == JSON_T_INT;

			if (strcmp(f[i].key, m->key))
				continue;
			if (f[i].seen || m->number != number)
				return -EINVAL;
			if (m->number)
				*(__s64 *)f[i].dst = m->value;
			else if (strscpy(f[i].dst, m->text, f[i].dst_cap) < 0)
				return -ENOSPC;
			f[i].seen = 1;
		}
	}
	return 0;
}

int json_parse(const char *data, size_t len, struct json_field *f, size_t n)
{
	__CPROVER_assert(n == 4 && !strcmp(f[0].key, "schema") &&
			 f[0].type == JSON_T_INT && !strcmp(f[1].key, "seq") &&
			 f[1].type == JSON_T_INT && !strcmp(f[2].key, "id") &&
			 f[2].type == JSON_T_STRING &&
			 f[2].dst_cap == TREE_STRING_MAX &&
			 !strcmp(f[3].key, "operation_digest") &&
			 f[3].type == JSON_T_STRING && f[3].dst_cap == 128,
			 "the record's four fields, each with its room");
	if (reading_back)
		return members_read(f, n);
	if (found.seen[0])
		*(__s64 *)f[0].dst = found.schema;
	if (found.seen[1])
		*(__s64 *)f[1].dst = found.seq;
	if (found.seen[2])
		memcpy(f[2].dst, found.id, sizeof(found.id));
	if (found.seen[3])
		memcpy(f[3].dst, found.digest, sizeof(found.digest));
	for (int i = 0; i < 4; i++)
		f[i].seen = found.seen[i];
	return found.ret;
}

/* "sha256:" and 64 hex digits of either case. */
static bool digest_text(const char *s)
{
	bool digits = true;

	for (int i = 7; i < 71; i++)
		digits &= (s[i] >= '0' && s[i] <= '9') ||
			  (s[i] >= 'a' && s[i] <= 'f') ||
			  (s[i] >= 'A' && s[i] <= 'F');
	return str_has_prefix(s, "sha256:") && digits && !s[71];
}

/* upatch-name proves which names upatch_name_valid() takes. */
static void parsed(void)
{
	struct found any;
	struct tree_pending out;
	size_t len, i, d;
	bool whole;
	char body;
	int ret;

	/*
	 * A global starts as zeros to CBMC, a local as anything. An id of
	 * up to ID_MAX bytes and a digest of up to one byte more than a
	 * sha256 digest has, each ended by a constant, where CBMC stops.
	 */
	found = any;
	found.id[ID_MAX] = '\0';
	found.digest[72] = '\0';
	__CPROVER_assume(found.ret <= 0 && i <= ID_MAX && d <= 72);
	ret = tree_pending_parse(&body, len, &out);
	whole = !found.ret && found.seen[0] && found.schema == 1 &&
		found.seen[1] && found.seq > 0 && found.seen[2] &&
		upatch_name_valid(found.id) && found.seen[3] &&
		digest_text(found.digest);
	__CPROVER_assert(!ret == whole,
			 "exactly a whole record of schema 1 is taken");
	if (ret) {
		__CPROVER_assert(ret == (found.ret ? found.ret : -EINVAL),
				 "the parser's error, or -EINVAL");
		return;
	}
	__CPROVER_assert(out.seq == found.seq && out.id[i] == found.id[i] &&
			 out.operation_digest[d] == found.digest[d],
			 "the record as read");
}

/* Whatever an operation holds as id and digest, the record has room for. */
_Static_assert(sizeof(((struct tree_operation *)0)->id) <=
	       sizeof(((struct tree_pending *)0)->id) &&
	       sizeof(((struct tree_operation *)0)->operation_digest) <=
	       sizeof(((struct tree_pending *)0)->operation_digest),
	       "an operation's id and digest fit the pending record");

/*
 * tree sync writes the record of an operation of a publication it has
 * checked: tree_operation_validate() refuses a seq that is not positive,
 * an id that is no upatch name and an operation digest that is no sha256
 * digest, which has 71 bytes. The id has up to ID_MAX bytes here; each
 * NUL is a constant, where CBMC stops.
 */
static void written(void)
{
	int any_emit, any_mkdir, any_write;
	struct tree_operation op;
	char text[sizeof(op.operation_digest)];
	__u8 digest[32];
	size_t i, d;
	int ret;

	emit_error = any_emit;
	mkdir_error = any_mkdir;
	write_error = any_write;
	__CPROVER_assume(emit_error <= 0 && mkdir_error <= 0 &&
			 write_error <= 0 && i <= ID_MAX && d <= 71);
	op.id[ID_MAX] = '\0';
	op.operation_digest[71] = '\0';
	/*
	 * The decoder moves past "sha256:" by a length CBMC keeps symbolic,
	 * and every read after that may be any byte of the object: in the
	 * 13 KB operation, that costs CBMC 9 GB. A copy of the field is an
	 * object of its 128 bytes alone.
	 */
	memcpy(text, op.operation_digest, sizeof(text));
	__CPROVER_assume(op.seq > 0 && upatch_name_valid(op.id) &&
			 !sha256_digest_decode(text, digest) &&
			 i <= strnlen(op.id, ID_MAX));
	ret = tree_pending_write(&op);
	__CPROVER_assert(closed && n_members == 4 &&
			 !strcmp(members[0].key, "schema") &&
			 members[0].number && members[0].value == 1 &&
			 !strcmp(members[1].key, "seq") && members[1].number &&
			 members[1].value == op.seq &&
			 !strcmp(members[2].key, "id") && !members[2].number &&
			 members[2].text == op.id &&
			 !strcmp(members[3].key, "operation_digest") &&
			 !members[3].number &&
			 members[3].text == op.operation_digest,
			 "schema 1 and the operation's seq, id and digest");
	if (emit_error || mkdir_error) {
		int error = emit_error ? emit_error : mkdir_error;

		__CPROVER_assert(ret == error && !n_written,
				 "no file without the document and its room");
		return;
	}
	__CPROVER_assert(n_written == 1 && ret == write_error,
			 "written once, with the result of the write");
	__CPROVER_assert(!read_back_ret && read_back.seq == op.seq &&
			 read_back.id[i] == op.id[i] &&
			 read_back.operation_digest[d] ==
			 op.operation_digest[d],
			 "what is written reads back as the operation's");
}

void harness(void)
{
	parsed();
	written();
}
