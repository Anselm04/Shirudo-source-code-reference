// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * on_record() of util/attest.c against step of the Lean model
 * Shirudo.AttestReplay, on every eventlog of up to LEN records: an init
 * record of any reset count, the load of a BPF upatch, the unload of a
 * Java one, a tree operation or a type the verifier does not read, each
 * with or without a word for its type, a digest, fields that decode and a
 * name upatch_name_valid() takes. After each record, on_record() refuses
 * exactly where step does, and keeps the records of the last init, their
 * digests, which of them are derived, inits_epoch and the last init's
 * reset count and digest as step does. Digests and decoded fields are one
 * byte each; hex_decode() and the event digests are stubs, as util/hex.c
 * and util/chain.c have proofs of their own, and the record types and
 * their tags copies of those of util/eventlog.c and util/chain.c.
 */

#include "proof.h"
/* on_record() keeps a missing reset count of -1 as a __u32 on purpose. */
#pragma CPROVER check push
#pragma CPROVER check disable "conversion"
#include "../../../util/attest.c"
#pragma CPROVER check pop

/*
 * The type into its record, at fixed indices: CBMC 5.95 places a write at
 * an index the data chooses wrongly in an object this large. The labels,
 * which only the report reads, keep their first 15 bytes.
 */
ssize_t strscpy(char *dst, const char *src, size_t size)
{
	bool end = false;
	size_t i;

	for (i = 0; i < 16 && i < size; i++) {
		char c = end || i + 1 == size || i == 15 ? '\0' : src[i];

		dst[i] = c;
		end = end || !c;
	}
	return 0;
}

int strsprintf(char *buf, size_t size, const char *fmt, ...)
{
	buf[0] = '\0';
	return 0;
}

/* A decoded value is its first byte, repeated; '!' and "" do not decode. */
int hex_decode(const char *hex, __u8 *out, size_t n)
{
	if (!hex[0] || hex[0] == '!')
		return -EINVAL;
	if (n == 32)
		memset(out, hex[0], 32);
	return 0;
}

int sha256_digest_decode(const char *digest, __u8 out[32])
{
	return hex_decode(digest + 7, out, 32);
}

bool upatch_name_valid(const char *name)
{
	return name[0] && name[0] != '!';
}

bool eventlog_upatch_record_parse(const char *record, __u32 *type,
				  bool *load)
{
	static const struct {
		char	record[16];
		__u32	type;
		bool	load;
	} records[] = {
		{ "upatch_load",	UPATCH_TYPE_BPF,	true },
		{ "upatch_unload",	UPATCH_TYPE_BPF,	false },
		{ "java_load",		UPATCH_TYPE_JAVA,	true },
		{ "java_unload",	UPATCH_TYPE_JAVA,	false },
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(records); i++) {
		if (!strcmp(records[i].record, record)) {
			*type = records[i].type;
			*load = records[i].load;
			return true;
		}
	}
	return false;
}

const char *chain_upatch_tag(__u32 type, bool load)
{
	switch (type) {
	case UPATCH_TYPE_BPF:
		return load ? "shirudo-upatch" : "shirudo-unload";
	case UPATCH_TYPE_JAVA:
		return load ? "shirudo-java" : "shirudo-java-unload";
	default:
		return NULL;
	}
}

/* 0 to 3 for the four upatch tags, 0x80 for any other. */
static __u8 tag_index(const char *tag)
{
	static const char tags[4][20] = {
		"shirudo-upatch", "shirudo-unload", "shirudo-java",
		"shirudo-java-unload",
	};
	__u8 i;

	for (i = 0; i < 4; i++) {
		if (!strcmp(tags[i], tag))
			return i;
	}
	return 0x80;
}

/*
 * An event's digest: a function of its fields, every byte the same. The
 * digests 'a' and 'b' differ in their low two bits only, so a record
 * derives its digest under the right tag and under no other: a BPF load
 * keeps its payload byte, a Java unload flips both bits.
 */
int chain_upatch_event(const char *tag, const char *name,
		       const __u8 payload[32], __u8 event[32])
{
	memset(event, (__u8)(payload[0] ^ (name[0] ^ 'n') ^ tag_index(tag)),
	       32);
	return 0;
}

int chain_tree_event(__s64 seq, const __u8 operation[32], __u8 event[32])
{
	memset(event, (__u8)(operation[0] ^ ((__u8)seq ^ 1)), 32);
	return 0;
}

int chain_key_event(const char *tag, const __u8 cert[32], __u8 event[32])
{
	memset(event, (__u8)(cert[0] ^ 0x20), 32);
	return 0;
}

enum kind { K_INIT, K_LOAD, K_JAVA_UNLOAD, K_TREE, K_OTHER };

/* step's state, each digest its byte. */
struct model {
	__u8	d[LEN];
	bool	derived[LEN];
	size_t	n;
	__u32	inits, epoch;
	bool	have;
	__u32	reset;
	__u8	init_digest;
};

static void fill(char *s, size_t len, char c)
{
	memset(s, c, len);
	s[len] = '\0';
}

/* One record into the parser's scratch, as json_parse() writes it. */
static void any_record(struct parse *p, enum kind k, bool word, char digest,
		       char field, bool fields_ok, bool name_ok, __s64 reset)
{
	static const char types[6][16] = {
		"init", "upatch_load", "java_unload", "tree_op", "zz", "Init",
	};
	size_t i;

	for (i = 0; i < sizeof(p->type); i++)
		p->type[i] = types[word ? k : 5][i];
	if (digest)
		fill(p->digest_hex, 64, digest);
	if (k == K_INIT) {
		p->rec_pcr = 9;
		p->rec_phase_pcr = 11;
		p->rec_reset = reset;
		fill(p->pcr_before_hex, 64, fields_ok ? 'a' : '!');
		fill(p->phase_before_hex, 64, 'a');
		fill(p->nv_name_hex, 2 * TPM_NAME_LEN, 'a');
		fill(p->anchor_digest_hex, 64, 'a');
		fill(p->chain_hex, 64, 'a');
		fill(p->writer_public_hex, 2, 'a');
	} else if (k == K_LOAD || k == K_JAVA_UNLOAD) {
		if (name_ok)
			strscpy_literal(p->upatch_name, "n");
		else
			strscpy_literal(p->upatch_name, "!");
		fill(p->upatch_payload_hex, 64, field);
	} else if (k == K_TREE) {
		p->tree_seq = 1;
		memcpy(p->tree_digest_hex, "sha256:", 7);
		fill(p->tree_digest_hex + 7, 64, field);
	}
}

/* step of Shirudo.AttestReplay, refusing as it does. */
static bool model_step(struct model *m, enum kind k, bool word, char digest,
		       char field, bool fields_ok, bool name_ok, __s64 reset)
{
	__u8 event = 0;
	bool have;

	if (!word || !digest)
		return false;
	if (k == K_INIT) {
		if (!fields_ok || reset > UINT32_MAX)
			return false;
		have = reset >= 0;
		m->inits++;
		m->epoch = m->inits == 1 ||
			   (have && m->have &&
			    (__u32)(reset & 0xffffffff) != m->reset) ?
			   1 : m->epoch + 1;
		m->have = have;
		m->reset = (__u32)(reset & 0xffffffff);
		m->init_digest = (__u8)digest;
		m->d[0] = (__u8)digest;
		m->derived[0] = false;
		m->n = 1;
		return true;
	}
	if ((k == K_LOAD || k == K_JAVA_UNLOAD) && !name_ok)
		return false;
	if (k == K_LOAD || k == K_TREE)
		event = (__u8)field;
	else if (k == K_JAVA_UNLOAD)
		event = (__u8)(field ^ 3);
	m->d[m->n] = (__u8)digest;
	m->derived[m->n] = k != K_OTHER && event == (__u8)digest;
	m->n++;
	return true;
}

static struct parse parse;

void harness(void)
{
	struct record recs[LEN];
	struct parse *p = &parse;
	struct model m = {};
	size_t i, j;

	p->recs = recs;
	p->rec_pcr = -1;
	p->rec_phase_pcr = -1;
	p->rec_reset = -1;
	for (i = 0; i < LEN; i++) {
		enum kind k;
		bool word, fields_ok, name_ok, took, model;
		char digest, field;
		__s64 reset;
		int ret;

		__CPROVER_assume(k >= K_INIT && k <= K_OTHER);
		__CPROVER_assume(!digest || digest == 'a' || digest == 'b');
		__CPROVER_assume(field == 'a' || field == 'b');
		__CPROVER_assume((reset >= -1 && reset <= 2) ||
				 reset == (__s64)UINT32_MAX + 1);
		any_record(p, k, word, digest, field, fields_ok, name_ok, reset);
		ret = on_record(p);
		took = !ret;
		model = model_step(&m, k, word, digest, field, fields_ok,
				   name_ok, reset);
		__CPROVER_assert(took == model, "refuses exactly where step does");
		if (!took)
			return;
		__CPROVER_assert(p->n_recs == m.n, "this register's records");
		for (j = 0; j < LEN && j < m.n; j++) {
			__CPROVER_assert(p->recs[j].digest[0] == m.d[j] &&
					 p->recs[j].digest[31] == m.d[j],
					 "each with its own digest");
			__CPROVER_assert(p->recs[j].derived == m.derived[j],
					 "derived as step says");
		}
		__CPROVER_assert(p->inits_epoch == m.epoch, "inits_epoch");
		__CPROVER_assert(p->init.have_reset_count == m.have &&
				 (!m.have || p->init.reset_count == m.reset),
				 "the last init's reset count");
		__CPROVER_assert(!m.inits || p->init.digest[0] == m.init_digest,
				 "the last init's digest");
	}
}
