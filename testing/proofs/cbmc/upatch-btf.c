// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What util/upatch_rodata.c prints of the BTF of a .upatch, which may come
 * unsigned, for BTF of NR_TYPES types and names of up to NAME_LEN bytes in
 * libbpf's stead: a name it prints is printable ASCII, a type whose
 * declaration it prints ends without a loop, and a type it unwraps is none
 * or one without a qualifier.
 */

#include "proof.h"
#include "../../../util/upatch_rodata.c"

#define NR_TYPES	4
#define NAME_LEN	6

struct model_type {
	struct btf_type t;
	struct btf_array a;
};

static struct model_type types[NR_TYPES];
static char names[NR_TYPES][NAME_LEN];

const struct btf_type *btf__type_by_id(const struct btf *btf, __u32 id)
{
	return id < NR_TYPES ? &types[id].t : NULL;
}

const char *btf__name_by_offset(const struct btf *btf, __u32 off)
{
	return off < NR_TYPES ? names[off] : NULL;
}

static bool printable(const char *s)
{
	size_t i;

	for (i = 0; i < NAME_LEN && s[i]; i++)
		if ((__u8)s[i] < 0x20 || (__u8)s[i] > 0x7e)
			return false;
	return true;
}

static bool qualifier(__u32 kind)
{
	return kind == BTF_KIND_TYPEDEF || kind == BTF_KIND_VOLATILE ||
	       kind == BTF_KIND_CONST || kind == BTF_KIND_RESTRICT ||
	       kind == BTF_KIND_TYPE_TAG;
}

static bool followed(__u32 kind)
{
	return kind == BTF_KIND_PTR || kind == BTF_KIND_VOLATILE ||
	       kind == BTF_KIND_CONST || kind == BTF_KIND_RESTRICT ||
	       kind == BTF_KIND_TYPE_TAG || kind == BTF_KIND_ARRAY;
}

/* Without a loop, a walk through NR_TYPES types ends in as many steps. */
static bool walk_ends(__u32 id)
{
	const struct model_type *m;
	__u32 step;

	for (step = 0; step <= NR_TYPES; step++) {
		if (!id)
			return true;
		if (id >= NR_TYPES)
			return false;
		m = &types[id];
		if (!followed(BTF_INFO_KIND(m->t.info)))
			return true;
		id = BTF_INFO_KIND(m->t.info) == BTF_KIND_ARRAY ? m->a.type :
								 m->t.type;
	}
	return false;
}

void harness(void)
{
	__u32 i, id, off, unwrapped;

	for (i = 0; i < NR_TYPES; i++) {
		struct model_type any_type;
		char any_name[NAME_LEN];

		types[i] = any_type;
		memcpy(names[i], any_name, NAME_LEN);
		__CPROVER_assume(!names[i][NAME_LEN - 1]);
	}
	if (btf_name_printable(NULL, off))
		__CPROVER_assert(off < NR_TYPES && printable(names[off]),
				 "a printable name");
	if (btf_decl_printable(NULL, id))
		__CPROVER_assert(walk_ends(id), "a declaration without a loop");
	unwrapped = btf_unwrap(NULL, id);
	__CPROVER_assert(!unwrapped ||
			 (unwrapped < NR_TYPES &&
			  !qualifier(BTF_INFO_KIND(types[unwrapped].t.info))),
			 "a type without a qualifier");
}
