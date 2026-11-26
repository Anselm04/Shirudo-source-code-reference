// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "format.h"
#include "io.h"
#include "json.h"
#include "log.h"
#include "malloc.h"
#include "upatch.h"
#include "upatch_rodata.h"

#define RODATA_MAPS_MAX	64
#define RODATA_JSON_MAX_DEPTH	8
#define RODATA_TEXT_MAX_VALUES	(1u << 20)
#define RODATA_DECL_MAX		32

struct rodata_map {
	char name[BPF_OBJ_NAME_LEN + 1];
	__u32 value_size;
	bool found;
};

struct rodata_view {
	struct btf *btf;
	const __u8 *bytes;
	__u32 data_offset;
	__u32 size;
	__u32 type_id;
};

static bool loader_lddw(const struct bpf_insn *insns, size_t count,
			size_t i, __u8 reg, __u32 *value)
{
	if (i + 1 >= count ||
	    insns[i].code != (BPF_LD | BPF_DW | BPF_IMM) ||
	    insns[i].dst_reg != reg ||
	    insns[i].src_reg != BPF_PSEUDO_MAP_IDX_VALUE ||
	    insns[i].off || insns[i].imm || insns[i + 1].code ||
	    insns[i + 1].off)
		return false;
	*value = (__u32)insns[i + 1].imm;
	return true;
}

static bool sys_bpf_call(const struct bpf_insn *insns, size_t count,
			 size_t i, __u32 *cmd, __u32 *attr, __u32 *attr_size)
{
	if (i < 4 || i >= count ||
	    insns[i].code != (BPF_JMP | BPF_CALL) ||
	    insns[i].imm != BPF_FUNC_sys_bpf ||
	    insns[i - 4].code != (BPF_ALU64 | BPF_MOV | BPF_K) ||
	    insns[i - 4].dst_reg != BPF_REG_1 ||
	    insns[i - 3].code != (BPF_LD | BPF_DW | BPF_IMM) ||
	    !loader_lddw(insns, count, i - 3, BPF_REG_2, attr) ||
	    insns[i - 1].code != (BPF_ALU64 | BPF_MOV | BPF_K) ||
	    insns[i - 1].dst_reg != BPF_REG_3)
		return false;
	*cmd = (__u32)insns[i - 4].imm;
	*attr_size = (__u32)insns[i - 1].imm;
	return true;
}

static bool map_create_slot(const struct bpf_insn *insns, size_t count,
			    size_t call, size_t next_call, __u32 *slot)
{
	size_t i;

	for (i = call + 1; i + 2 < next_call; i++) {
		__u32 off;

		if (loader_lddw(insns, count, i, BPF_REG_1, &off) &&
		    insns[i + 2].code == (BPF_STX | BPF_W | BPF_MEM) &&
		    insns[i + 2].dst_reg == BPF_REG_1 &&
		    insns[i + 2].src_reg == BPF_REG_7 &&
		    !insns[i + 2].off && !(off % sizeof(__u32)) &&
		    off / sizeof(__u32) < RODATA_MAPS_MAX) {
			*slot = off / sizeof(__u32);
			return true;
		}
	}
	return false;
}

static bool map_update_slot(const struct bpf_insn *insns, size_t count,
			    size_t call, __u32 attr, __u32 *slot)
{
	size_t start = call > 48 ? call - 48 : 0;
	size_t i;
	__u32 map_fd_off = attr + offsetof(union bpf_attr, map_fd);

	for (i = start; i + 5 < call; i++) {
		__u32 fd_array_off, dest_off;

		if (!loader_lddw(insns, count, i, BPF_REG_2, &fd_array_off) ||
		    insns[i + 2].code != (BPF_LDX | BPF_W | BPF_MEM) ||
		    insns[i + 2].dst_reg != BPF_REG_0 ||
		    insns[i + 2].src_reg != BPF_REG_2 || insns[i + 2].off ||
		    !loader_lddw(insns, count, i + 3, BPF_REG_1, &dest_off) ||
		    dest_off != map_fd_off ||
		    insns[i + 5].code != (BPF_STX | BPF_W | BPF_MEM) ||
		    insns[i + 5].dst_reg != BPF_REG_1 ||
		    insns[i + 5].src_reg != BPF_REG_0 || insns[i + 5].off ||
		    fd_array_off % sizeof(__u32) ||
		    fd_array_off / sizeof(__u32) >= RODATA_MAPS_MAX)
			continue;
		*slot = fd_array_off / sizeof(__u32);
		return true;
	}
	return false;
}

/*
 * The data offset the loader stores into the attr field at field before
 * the sys_bpf() call at call, as libbpf's gen_loader writes a pointer
 * into its data.
 */
static bool loader_store_source(const struct bpf_insn *insns, size_t count,
				size_t call, __u32 field, __u32 *source)
{
	size_t start = call > 24 ? call - 24 : 0;
	size_t i;

	for (i = start; i + 4 < call; i++) {
		__u32 source_off, dest_off;

		if (!loader_lddw(insns, count, i, BPF_REG_0, &source_off) ||
		    !loader_lddw(insns, count, i + 2, BPF_REG_1, &dest_off) ||
		    dest_off != field ||
		    insns[i + 4].code != (BPF_STX | BPF_DW | BPF_MEM) ||
		    insns[i + 4].dst_reg != BPF_REG_1 ||
		    insns[i + 4].src_reg != BPF_REG_0 || insns[i + 4].off)
			continue;
		*source = source_off;
		return true;
	}
	return false;
}

static bool map_name_rodata(const char *name)
{
	static const char suffix[] = ".rodata";
	size_t name_len = strlen(name), suffix_len = sizeof(suffix) - 1;

	return name_len >= suffix_len &&
	       !strcmp(name + name_len - suffix_len, suffix);
}

static int find_rodata_data(const struct upatch *u,
			    const struct btf *btf, __u32 datasec_id,
			    struct rodata_view *view)
{
	const struct btf_type *sec = btf__type_by_id(btf, datasec_id);
	const struct bpf_insn *insns = upatch_loader(u);
	const __u8 *data = upatch_data(u);
	struct rodata_map maps[RODATA_MAPS_MAX] = {};
	size_t count = u->hdr.loader_insns_len / sizeof(*insns), i;
	__u32 sec_size;
	int ret = -ENODATA;

	if (!sec || BTF_INFO_KIND(sec->info) != BTF_KIND_DATASEC ||
	    u->hdr.loader_insns_len % sizeof(*insns))
		return -EINVAL;
	sec_size = sec->size;
	for (i = 4; i < count; i++) {
		__u32 cmd, attr_off, attr_size;

		if (!sys_bpf_call(insns, count, i, &cmd, &attr_off,
				  &attr_size))
			continue;
		if (cmd == BPF_MAP_CREATE) {
			union bpf_attr attr = {};
			__u32 end, next;
			char name[BPF_OBJ_NAME_LEN + 1];

			if (attr_size > sizeof(attr) ||
			    attr_size < offsetofend(union bpf_attr, map_name) ||
			    attr_off > u->hdr.data_len ||
			    attr_size > u->hdr.data_len - attr_off)
				return -EINVAL;
			memcpy(&attr, data + attr_off, attr_size);
			memcpy(name, attr.map_name, BPF_OBJ_NAME_LEN);
			name[BPF_OBJ_NAME_LEN] = '\0';
			end = (__u32)count;
			for (next = (__u32)i + 1; next < count; next++) {
				__u32 ignored_cmd, ignored_attr, ignored_size;

				if (sys_bpf_call(insns, count, next, &ignored_cmd,
						 &ignored_attr, &ignored_size)) {
					end = next;
					break;
				}
			}
			if (map_name_rodata(name)) {
				__u32 slot;

				BUILD_BUG_ON(sizeof(maps[0].name) != sizeof(name));
				if (!map_create_slot(insns, count, i, end, &slot))
					return -EOPNOTSUPP;
				maps[slot].value_size = attr.value_size;
				maps[slot].found = true;
				memcpy(maps[slot].name, name, sizeof(name));
			}
		} else if (cmd == BPF_MAP_UPDATE_ELEM) {
			__u32 slot, value_field, value_off;

			if (check_add_overflow(attr_off,
					       offsetof(union bpf_attr, value),
					       &value_field) ||
			    !map_update_slot(insns, count, i, attr_off, &slot) ||
			    !loader_store_source(insns, count, i, value_field,
						 &value_off))
				continue;
			if (!maps[slot].found)
				continue;
			if (maps[slot].value_size != sec_size ||
			    value_off > u->hdr.data_len ||
			    maps[slot].value_size > u->hdr.data_len - value_off)
				return -EINVAL;
			view->bytes = data + value_off;
			view->data_offset = value_off;
			view->size = sec_size;
			view->type_id = datasec_id;
			return 0;
		}
	}
	return ret;
}

/*
 * The BTF the loader's one BPF_BTF_LOAD loads: the offset in data it
 * stores into attr.btf, and the attr.btf_size beside it.
 */
static int loader_btf(const struct upatch *u, __u32 *off, __u32 *size)
{
	const struct bpf_insn *insns = upatch_loader(u);
	const __u8 *data = upatch_data(u);
	size_t count = u->hdr.loader_insns_len / sizeof(*insns), i;
	bool found = false;

	if (!data)
		return -ENOENT;
	if (u->hdr.loader_insns_len % sizeof(*insns))
		return -EINVAL;
	for (i = 4; i < count; i++) {
		__u32 cmd, attr_off, attr_size, field, btf_off;
		union bpf_attr attr = {};

		if (!sys_bpf_call(insns, count, i, &cmd, &attr_off,
				  &attr_size) || cmd != BPF_BTF_LOAD)
			continue;
		if (found)
			return -E2BIG;
		if (attr_size > sizeof(attr) ||
		    attr_size < offsetofend(union bpf_attr, btf_size) ||
		    attr_off > u->hdr.data_len ||
		    attr_size > u->hdr.data_len - attr_off)
			return -EINVAL;
		memcpy(&attr, data + attr_off, attr_size);
		if (check_add_overflow(attr_off, offsetof(union bpf_attr, btf),
				       &field) ||
		    !loader_store_source(insns, count, i, field, &btf_off) ||
		    btf_off > u->hdr.data_len ||
		    attr.btf_size > u->hdr.data_len - btf_off)
			return -EINVAL;
		*off = btf_off;
		*size = attr.btf_size;
		found = true;
	}
	return found ? 0 : -ENOENT;
}

static int btf_rodata_btf(const struct upatch *u,
			  struct rodata_view *view)
{
	const __u8 *data = upatch_data(u);
	__u32 btf_off, btf_size;
	struct btf *btf;
	__s32 id;
	int ret;

	ret = loader_btf(u, &btf_off, &btf_size);
	if (ret)
		return ret;
	btf = btf__new(data + btf_off, btf_size);
	if (libbpf_get_error(btf))
		return -ENOENT;
	id = btf__find_by_name_kind(btf, ".rodata", BTF_KIND_DATASEC);
	if (id <= 0) {
		btf__free(btf);
		return -ENOENT;
	}
	view->btf = btf;
	/*
	 * The header is not signed: .rodata is where the signed loader
	 * takes it from, and a header that names another offset would aim
	 * a rewrite the operator then signs at other bytes.
	 */
	ret = find_rodata_data(u, btf, (__u32)id, view);
	if (!ret && u->rodata_offset_in_header &&
	    view->data_offset != u->hdr.rodata_data_off)
		return -EINVAL;
	return ret;
}

int upatch_rodata_data_offset(const struct upatch *u, __u32 *offset)
{
	struct rodata_view view = {};
	int ret;

	if (!u || !offset)
		return -EINVAL;
	ret = btf_rodata_btf(u, &view);
	if (!ret)
		*offset = view.data_offset;
	btf__free(view.btf);
	return ret;
}

int upatch_rodata_symbol_range(const struct upatch *u,
			       const char *symbol,
			       struct rodata_range *range)
{
	struct rodata_view view = {};
	const struct btf_type *sec;
	const struct btf_var_secinfo *vars;
	bool found = false;
	__u32 i;
	int ret;

	if (!u || !symbol || !symbol[0] || !range)
		return -EINVAL;
	ret = btf_rodata_btf(u, &view);
	if (ret) {
		btf__free(view.btf);
		return ret;
	}
	sec = btf__type_by_id(view.btf, view.type_id);
	if (!sec || BTF_INFO_KIND(sec->info) != BTF_KIND_DATASEC) {
		ret = -EINVAL;
		goto out;
	}
	vars = (const struct btf_var_secinfo *)(sec + 1);
	for (i = 0; i < BTF_INFO_VLEN(sec->info); i++) {
		const struct btf_type *var;
		const char *name;
		__u32 offset, size, end;

		var = btf__type_by_id(view.btf, vars[i].type);
		if (!var || BTF_INFO_KIND(var->info) != BTF_KIND_VAR)
			continue;
		name = btf__name_by_offset(view.btf, var->name_off);
		if (!name)
			continue;
		if (strcmp(name, symbol))
			continue;
		if (found) {
			ret = -EEXIST;
			goto out;
		}
		offset = vars[i].offset;
		size = vars[i].size;
		if (check_add_overflow(offset, size, &end) || end > view.size ||
		    check_add_overflow(view.data_offset, end, &end) ||
		    end > u->hdr.data_len) {
			ret = -EINVAL;
			goto out;
		}
		range->offset = view.data_offset + offset;
		range->size = size;
		found = true;
	}
	ret = found ? 0 : -ENOENT;
out:
	btf__free(view.btf);
	return ret;
}

/*
 * The BTF may come from an unsigned package, and its names go to the
 * terminal: take printable ASCII alone, all that a kernel would load.
 */
static bool btf_name_printable(const struct btf *btf, __u32 off)
{
	const char *name = btf__name_by_offset(btf, off);

	if (!name)
		return false;
	for (; *name; name++)
		if ((__u8)*name < 0x20 || (__u8)*name > 0x7e)
			return false;
	return true;
}

static __u32 btf_unwrap(const struct btf *btf, __u32 id)
{
	const struct btf_type *t;
	__u32 i;

	for (i = 0; i < RODATA_JSON_MAX_DEPTH; i++) {
		t = btf__type_by_id(btf, id);
		if (!t)
			return 0;
		switch (BTF_INFO_KIND(t->info)) {
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_TYPE_TAG:
			id = t->type;
			break;
		default:
			return id;
		}
	}
	return 0;
}

static int append_type_name(const struct btf *btf, __u32 id, char *buf,
			    size_t cap, size_t *off, __u32 depth)
{
	const struct btf_type *t;
	const char *name;
	__u16 kind;
	int n;

	if (depth >= RODATA_JSON_MAX_DEPTH || *off >= cap)
		return -E2BIG;
	t = btf__type_by_id(btf, id);
	if (!t)
		return -EINVAL;
	kind = BTF_INFO_KIND(t->info);
	if (!btf_name_printable(btf, t->name_off))
		return -EINVAL;
	name = btf__name_by_offset(btf, t->name_off);
	if (kind == BTF_KIND_TYPEDEF && name && name[0]) {
		n = strsprintf(buf + *off, cap - *off, "%s", name);
		if (n < 0)
			return -ENOSPC;
		*off += (size_t)n;
		return 0;
	}
	if (kind == BTF_KIND_TYPEDEF || kind == BTF_KIND_VOLATILE ||
	    kind == BTF_KIND_CONST || kind == BTF_KIND_RESTRICT ||
	    kind == BTF_KIND_TYPE_TAG)
		return append_type_name(btf, t->type, buf, cap, off, depth + 1);
	if (kind == BTF_KIND_ARRAY) {
		const struct btf_array *a = (const struct btf_array *)(t + 1);

		if (append_type_name(btf, a->type, buf, cap, off, depth + 1))
			return -EINVAL;
		n = strsprintf(buf + *off, cap - *off, "[%u]", a->nelems);
		if (n < 0)
			return -ENOSPC;
		*off += (size_t)n;
		return 0;
	}
	if (kind == BTF_KIND_PTR) {
		if (append_type_name(btf, t->type, buf, cap, off, depth + 1))
			return -EINVAL;
		n = strsprintf(buf + *off, cap - *off, " *");
		if (n < 0)
			return -ENOSPC;
		*off += (size_t)n;
		return 0;
	}
	if (name && name[0]) {
		n = strsprintf(buf + *off, cap - *off, "%s%s",
			       kind == BTF_KIND_STRUCT ? "struct " :
			       kind == BTF_KIND_UNION ? "union " :
			       kind == BTF_KIND_ENUM ? "enum " : "", name);
	} else {
		const char *fallback = "?";

		switch (kind) {
		case BTF_KIND_INT:
			fallback = "integer";
			break;
		case BTF_KIND_STRUCT:
			fallback = "struct";
			break;
		case BTF_KIND_UNION:
			fallback = "union";
			break;
		case BTF_KIND_ENUM:
		case BTF_KIND_ENUM64:
			fallback = "enum";
			break;
		case BTF_KIND_FLOAT:
			fallback = "float";
			break;
		case BTF_KIND_FWD:
			fallback = "forward declaration";
			break;
		default:
			break;
		}
		n = strsprintf(buf + *off, cap - *off, "%s", fallback);
	}
	if (n < 0)
		return -ENOSPC;
	*off += (size_t)n;
	return 0;
}

static int json_number(struct json_emit *e, __u64 value,
		       bool is_signed)
{
	char number[32];
	int n;

	if (!is_signed) {
		json_u64_value(e, value);
		return e->err;
	}
	n = strsprintf(number, sizeof(number), "%lld", (__s64)value);
	if (n < 0)
		return n;
	json_raw_value(e, number, (size_t)n);
	return e->err;
}

static int btf_integer(const struct btf_type *t, const void *bytes,
		       size_t size, __u64 *value, bool *is_signed,
		       bool *is_bool)
{
	__u32 enc, bits, bit_off;
	__u32 i;
	__u64 result = 0;

	if (t->size > size || !t->size || t->size > sizeof(result))
		return -EINVAL;
	enc = *(__u32 *)(t + 1);
	bits = BTF_INT_BITS(enc);
	bit_off = BTF_INT_OFFSET(enc);
	if (!bits || bits > 64 || bit_off + bits > t->size * 8)
		return -EINVAL;
	for (i = 0; i < bits; i++) {
		__u32 b = bit_off + i;

		if (((const __u8 *)bytes)[b / 8] & (1u << (b % 8)))
			result |= (__u64)1 << i;
	}
	*is_signed = (BTF_INT_ENCODING(enc) & BTF_INT_SIGNED) != 0;
	*is_bool = (BTF_INT_ENCODING(enc) & BTF_INT_BOOL) != 0;
	if (*is_signed && bits < 64 && (result & ((__u64)1 << (bits - 1))))
		result |= ~(((__u64)1 << bits) - 1);
	*value = result;
	return 0;
}

static void json_hex(struct json_emit *e, const void *bytes,
		     size_t size)
{
	static const char hex[] = "0123456789abcdef";
	char *text;
	const __u8 *p = bytes;
	size_t i, cap;

	cap = size_add(size_mul(size, 2), 3);
	if (cap > JSON_MAX_BYTES) {
		e->err = -E2BIG;
		return;
	}
	text = xmalloc(cap);
	if (!text) {
		e->err = -ENOMEM;
		return;
	}
	text[0] = '0';
	text[1] = 'x';
	for (i = 0; i < size; i++) {
		text[2 + i * 2] = hex[p[i] >> 4];
		text[3 + i * 2] = hex[p[i] & 0x0f];
	}
	text[2 + size * 2] = '\0';
	json_str_value(e, text);
	xfree(text, cap);
}

static int json_btf_value(struct json_emit *e, const struct btf *btf,
			  __u32 type_id, const __u8 *bytes, size_t size,
			  __u32 depth)
{
	const struct btf_type *t;
	__u16 kind;
	int ret;

	if (depth >= RODATA_JSON_MAX_DEPTH || !type_id || !bytes)
		return -EINVAL;
	type_id = btf_unwrap(btf, type_id);
	t = btf__type_by_id(btf, type_id);
	if (!t)
		return -EINVAL;
	kind = BTF_INFO_KIND(t->info);
	if (kind == BTF_KIND_INT) {
		__u64 value;
		bool sign, boolean;

		ret = btf_integer(t, bytes, size, &value, &sign, &boolean);
		if (ret)
			return ret;
		if (boolean)
			json_raw_value(e, value ? "true" : "false", value ? 4 : 5);
		else
			return json_number(e, value, sign);
		return e->err;
	}
	if (kind == BTF_KIND_ENUM || kind == BTF_KIND_ENUM64) {
		__u64 value = 0;
		bool sign = BTF_INFO_KFLAG(t->info);
		__u32 i, vlen = BTF_INFO_VLEN(t->info);
		const char *enum_name = NULL;

		if (!t->size || t->size > sizeof(value) || t->size > size)
			return -EINVAL;
		for (i = 0; i < t->size; i++)
			value |= (__u64)bytes[i] << (i * 8);
		if (sign && t->size < sizeof(value) &&
		    (value & ((__u64)1 << (t->size * 8 - 1))))
			value |= ~(((__u64)1 << (t->size * 8)) - 1);
		if (kind == BTF_KIND_ENUM) {
			const struct btf_enum *vals = (const struct btf_enum *)(t + 1);
			__u32 v = (__u32)value;

			for (i = 0; i < vlen; i++)
				if ((__u32)vals[i].val == v) {
					enum_name = btf__name_by_offset(btf,
									vals[i].name_off);
					break;
				}
		} else {
			const struct btf_enum64 *vals =
				(const struct btf_enum64 *)(t + 1);

			for (i = 0; i < vlen; i++) {
				__u64 v = (__u64)vals[i].val_lo32 |
					  (__u64)vals[i].val_hi32 << 32;

				if (v == value) {
					enum_name = btf__name_by_offset(btf,
									vals[i].name_off);
					break;
				}
			}
		}
		json_obj_value_open(e);
		if (enum_name && enum_name[0])
			json_kv_string(e, "name", enum_name);
		json_key(e, "value");
		json_number(e, value, sign);
		json_obj_close(e);
		return e->err;
	}
	if (kind == BTF_KIND_STRUCT) {
		const struct btf_member *m = (const struct btf_member *)(t + 1);
		__u32 vlen = BTF_INFO_VLEN(t->info), i;

		json_obj_value_open(e);
		for (i = 0; i < vlen && !e->err; i++) {
			__u32 bit_off = BTF_INFO_KFLAG(t->info) ?
				BTF_MEMBER_BIT_OFFSET(m[i].offset) : m[i].offset;
			__u32 bit_size = BTF_INFO_KFLAG(t->info) ?
				BTF_MEMBER_BITFIELD_SIZE(m[i].offset) : 0;
			__u32 byte_off = bit_off / 8;
			const char *name = btf__name_by_offset(btf,
								m[i].name_off);
			__s64 member_size = btf__resolve_size(btf, m[i].type);
			char fallback[24];

			if (!name || !name[0]) {
				if (strsprintf(fallback, sizeof(fallback), "member_%u",
					       i) < 0)
					return -EINVAL;
				name = fallback;
			}
			json_key(e, name);
			if (bit_size) {
				__u32 n = DIV_ROUND_UP(bit_off % 8 + bit_size, 8);
				__u32 j;
				const struct btf_type *member_type =
					btf__type_by_id(btf,
							btf_unwrap(btf, m[i].type));
				__u32 enc;
				__u64 val = 0;
				bool sign;

				if (bit_size > 64 || byte_off + n > size ||
				    !member_type ||
				    BTF_INFO_KIND(member_type->info) != BTF_KIND_INT)
					return -EINVAL;
				enc = *(__u32 *)(member_type + 1);
				sign = BTF_INT_ENCODING(enc) & BTF_INT_SIGNED;
				for (j = 0; j < bit_size; j++) {
					__u32 pos = bit_off + j;

					if (bytes[pos / 8] & (1u << (pos % 8)))
						val |= (__u64)1 << j;
				}
				if (sign && bit_size < 64 &&
				    (val & ((__u64)1 << (bit_size - 1))))
					val |= ~(((__u64)1 << bit_size) - 1);
				json_number(e, val, sign);
			} else {
				if (member_size < 0 || byte_off > size ||
				    (size_t)member_size > size - byte_off)
					return -EINVAL;
				ret = json_btf_value(e, btf, m[i].type,
						     bytes + byte_off,
						     (size_t)member_size,
						     depth + 1);
				if (ret)
					return ret;
			}
		}
		json_obj_close(e);
		return e->err;
	}
	if (kind == BTF_KIND_ARRAY) {
		const struct btf_array *a = (const struct btf_array *)(t + 1);
		__s64 elem_size = btf__resolve_size(btf, a->type);
		size_t total;
		__u32 i;

		if (elem_size < 0 ||
		    check_mul_overflow(elem_size, a->nelems, &total) ||
		    total > size)
			return -EINVAL;
		json_arr_open_value(e);
		for (i = 0; i < a->nelems && !e->err; i++) {
			if (!elem_size)
				return -EINVAL;
			ret = json_btf_value(e, btf, a->type,
					     bytes + (size_t)i * elem_size,
					     (size_t)elem_size, depth + 1);
			if (ret)
				return ret;
		}
		json_arr_close(e);
		return e->err;
	}
	if (kind == BTF_KIND_PTR) {
		__u64 value = 0;
		char text[32];
		int n;

		if (size > sizeof(value))
			return -EINVAL;
		memcpy(&value, bytes, size);
		n = strsprintf(text, sizeof(text), "0x%llx",
			       (__u64)value);
		if (n < 0)
			return n;
		json_str_value(e, text);
		return e->err;
	}
	json_hex(e, bytes, size);
	return e->err;
}

static const char *btf_var_name(const struct btf *btf,
				const struct btf_var_secinfo *var)
{
	const struct btf_type *t = btf__type_by_id(btf, var->type);

	return t && BTF_INFO_KIND(t->info) == BTF_KIND_VAR &&
	       btf_name_printable(btf, t->name_off) ?
	       btf__name_by_offset(btf, t->name_off) : NULL;
}

static int btf_var_type(const struct btf *btf,
			const struct btf_var_secinfo *var, __u32 *type_id)
{
	const struct btf_type *t = btf__type_by_id(btf, var->type);

	if (!t || BTF_INFO_KIND(t->info) != BTF_KIND_VAR)
		return -EINVAL;
	*type_id = t->type;
	return 0;
}

static __printf(2, 0) void print_text(void *ctx, const char *fmt,
				       va_list args)
{
	FILE *fp = ctx;

	vfprintf(fp, fmt, args);
}

/*
 * The cast libbpf's dumper writes before a value spells its type through
 * modifiers, pointers and arrays, and stops at no loop: a pointer to
 * itself grows its stack until memory runs out, and a function prototype
 * whose parameter leads back to it recurses until the stack does.
 */
static bool btf_decl_printable(const struct btf *btf, __u32 id)
{
	const struct btf_type *t;
	__u32 step;

	for (step = 0; step < RODATA_DECL_MAX; step++) {
		if (!id)
			return true;
		t = btf__type_by_id(btf, id);
		if (!t)
			return false;
		switch (BTF_INFO_KIND(t->info)) {
		case BTF_KIND_PTR:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_TYPE_TAG:
			id = t->type;
			break;
		case BTF_KIND_ARRAY:
			id = ((const struct btf_array *)(t + 1))->type;
			break;
		case BTF_KIND_INT:
		case BTF_KIND_ENUM:
		case BTF_KIND_ENUM64:
		case BTF_KIND_FWD:
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_FLOAT:
			return btf_name_printable(btf, t->name_off);
		default:
			return false;
		}
	}
	return false;
}

/* What the dumper visits of a value of a type: values printed, types deep. */
struct dump_cost {
	__u32	values;
	__u32	height;
};

/*
 * libbpf's dumper follows member, element and modifier types with no
 * bound, and the BTF may come from an unsigned package: a VAR whose type
 * is the DATASEC holding it sends it round until the stack is gone, and
 * billions of elements, of zero size or not, or members laid over the
 * same bytes keep it busy. Walk what it would follow first, through value
 * types alone, with the cast and the member and enumerator names it would
 * print, and count what it would visit: -EINVAL for more than
 * RODATA_JSON_MAX_DEPTH types deep, -E2BIG for more than
 * RODATA_TEXT_MAX_VALUES values. cost keeps the counts of the types found
 * fine, so a type reached again brings its depth and values along.
 */
static int btf_dump_cost(const struct btf *btf, __u32 id, __u32 depth,
			 struct dump_cost *cost)
{
	const struct btf_type *t = btf__type_by_id(btf, id);
	struct dump_cost c = { .values = 1, .height = 1 };
	const struct btf_enum64 *e64;
	const struct btf_member *m;
	const struct btf_array *a;
	const struct btf_enum *e;
	__u32 i, child;
	int ret;

	if (!t || depth >= RODATA_JSON_MAX_DEPTH)
		return -EINVAL;
	if (cost[id].values)
		return 0;
	if (!btf_decl_printable(btf, id))
		return -EINVAL;
	switch (BTF_INFO_KIND(t->info)) {
	case BTF_KIND_INT:
	case BTF_KIND_PTR:
	case BTF_KIND_FLOAT:
		break;
	case BTF_KIND_ENUM:
		e = (const struct btf_enum *)(t + 1);
		for (i = 0; i < BTF_INFO_VLEN(t->info); i++)
			if (!btf_name_printable(btf, e[i].name_off))
				return -EINVAL;
		break;
	case BTF_KIND_ENUM64:
		e64 = (const struct btf_enum64 *)(t + 1);
		for (i = 0; i < BTF_INFO_VLEN(t->info); i++)
			if (!btf_name_printable(btf, e64[i].name_off))
				return -EINVAL;
		break;
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_TYPE_TAG:
		ret = btf_dump_cost(btf, t->type, depth + 1, cost);
		if (ret)
			return ret;
		c.values = cost[t->type].values;
		c.height = cost[t->type].height + 1;
		break;
	case BTF_KIND_ARRAY:
		a = (const struct btf_array *)(t + 1);
		if (a->nelems && btf__resolve_size(btf, a->type) <= 0)
			return -EINVAL;
		ret = btf_dump_cost(btf, a->type, depth + 1, cost);
		if (ret)
			return ret;
		if (check_mul_overflow(cost[a->type].values, a->nelems,
				       &child) ||
		    check_add_overflow(c.values, child, &c.values))
			return -E2BIG;
		c.height = cost[a->type].height + 1;
		break;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		m = (const struct btf_member *)(t + 1);
		for (i = 0; i < BTF_INFO_VLEN(t->info); i++) {
			if (!btf_name_printable(btf, m[i].name_off))
				return -EINVAL;
			ret = btf_dump_cost(btf, m[i].type, depth + 1, cost);
			if (ret)
				return ret;
			if (check_add_overflow(c.values,
					       cost[m[i].type].values,
					       &c.values))
				return -E2BIG;
			c.height = max(c.height, cost[m[i].type].height + 1);
		}
		break;
	default:
		return -EINVAL;
	}
	if (c.height > RODATA_JSON_MAX_DEPTH)
		return -EINVAL;
	if (c.values > RODATA_TEXT_MAX_VALUES)
		return -E2BIG;
	cost[id] = c;
	return 0;
}

static int print_rodata_text(const struct upatch *u,
			     const char *path, const struct rodata_view *view)
{
	struct btf_dump_type_data_opts opts = {
		.sz = sizeof(opts),
		.indent_str = "  ",
		.emit_zeroes = true,
		.emit_strings = true,
	};
	struct btf_dump *dump;
	const struct btf_type *sec = btf__type_by_id(view->btf,
							    view->type_id);
	const struct btf_var_secinfo *vars =
		(const struct btf_var_secinfo *)(sec + 1);
	__u32 i, values = 0, vlen = BTF_INFO_VLEN(sec->info);
	__u32 types = btf__type_cnt(view->btf);
	char name[UPATCH_NAME_MAX + 1];
	struct dump_cost *cost;
	int ret = 0;

	upatch_header_name(u, name);
	text_sanitize(name, strlen(name), false);
	printf("upatch %s (", name);
	fputs_sanitized(path, stdout);
	printf(") .rodata: %u bytes at data+%u, file+%u\n", view->size,
	       view->data_offset, u->hdr.data_off + view->data_offset);
	cost = xcalloc(types, sizeof(*cost));
	if (!cost)
		return -ENOMEM;
	dump = btf_dump__new(view->btf, print_text, stdout, NULL);
	if (libbpf_get_error(dump)) {
		xfree(cost, types * sizeof(*cost));
		return -EINVAL;
	}
	for (i = 0; i < vlen; i++) {
		__u32 type_id;
		const char *var_name = btf_var_name(view->btf, &vars[i]);
		char type[256] = {};
		size_t type_off = 0;

		if (!var_name || !var_name[0] ||
		    btf_var_type(view->btf, &vars[i], &type_id)) {
			ret = -EINVAL;
			goto out;
		}
		ret = append_type_name(view->btf, type_id, type,
				       sizeof(type), &type_off, 0);
		if (ret)
			goto out;
		if (vars[i].offset > view->size ||
		    vars[i].size > view->size - vars[i].offset) {
			ret = -EINVAL;
			goto out;
		}
		ret = btf_dump_cost(view->btf, type_id, 0, cost);
		if (!ret &&
		    (check_add_overflow(values, cost[type_id].values, &values) ||
		     values > RODATA_TEXT_MAX_VALUES))
			ret = -E2BIG;
		if (ret == -E2BIG)
			pr_err("BTF text output exceeds %u values",
			       RODATA_TEXT_MAX_VALUES);
		if (ret)
			goto out;
		printf("\n%s: %s, size=%u, rodata+%u, data+%u, file+%u = ",
		       var_name, type, vars[i].size, vars[i].offset,
		       view->data_offset + vars[i].offset,
		       u->hdr.data_off + view->data_offset + vars[i].offset);
		ret = btf_dump__dump_type_data(dump, type_id,
					       view->bytes + vars[i].offset,
					       vars[i].size, &opts);
		if (ret < 0)
			goto out;
		putchar('\n');
	}
	putchar('\n');
out:
	btf_dump__free(dump);
	xfree(cost, types * sizeof(*cost));
	return min(ret, 0);
}

static int print_rodata_json(const struct upatch *u,
			     const char *path, const struct rodata_view *view)
{
	const struct btf_type *sec = btf__type_by_id(view->btf,
							    view->type_id);
	const struct btf_var_secinfo *vars =
		(const struct btf_var_secinfo *)(sec + 1);
	struct json_emit e = { .max = JSON_MAX_BYTES };
	__u32 i, vlen = BTF_INFO_VLEN(sec->info);
	char name[UPATCH_NAME_MAX + 1];
	int ret = 0;

	upatch_header_name(u, name);
	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_kv_string_lossy(&e, "upatch", name);
	json_kv_string_lossy(&e, "path", path);
	json_kv_string(&e, "section", ".rodata");
	json_kv_int(&e, "size", view->size);
	json_kv_int(&e, "data_offset", view->data_offset);
	json_kv_int(&e, "file_offset", u->hdr.data_off + view->data_offset);
	json_arr_open(&e, "variables");
	for (i = 0; i < vlen && !e.err; i++) {
		const char *var_name = btf_var_name(view->btf, &vars[i]);
		char type[256] = {};
		size_t type_off = 0;
		__u32 type_id;

		if (!var_name || !var_name[0] ||
		    btf_var_type(view->btf, &vars[i], &type_id)) {
			ret = -EINVAL;
			break;
		}
		ret = append_type_name(view->btf, type_id, type,
				       sizeof(type), &type_off, 0);
		if (ret)
			break;
		if (vars[i].offset > view->size ||
		    vars[i].size > view->size - vars[i].offset) {
			ret = -EINVAL;
			break;
		}
		json_obj_open(&e);
		json_kv_string(&e, "name", var_name);
		json_kv_string(&e, "type", type);
		json_kv_int(&e, "size", vars[i].size);
		json_kv_int(&e, "rodata_offset", vars[i].offset);
		json_kv_int(&e, "data_offset",
			    view->data_offset + vars[i].offset);
		json_kv_int(&e, "file_offset",
			    u->hdr.data_off + view->data_offset + vars[i].offset);
		json_key(&e, "value");
		ret = json_btf_value(&e, view->btf, type_id,
				     view->bytes + vars[i].offset,
				     vars[i].size, 0);
		json_obj_close(&e);
		if (ret)
			break;
	}
	json_arr_close(&e);
	json_obj_close(&e);
	if (!ret && e.err)
		ret = e.err;
	if (!ret)
		ret = write_complete(STDOUT_FILENO, e.buf, e.len);
	if (!ret)
		ret = write_complete(STDOUT_FILENO, "\n", 1);
	if (e.err == -E2BIG)
		pr_err("BTF JSON output exceeds %u bytes", JSON_MAX_BYTES);
	xfree(e.buf, e.cap);
	return ret;
}

int upatch_rodata_print(const struct upatch *u, const char *path,
			bool json)
{
	struct rodata_view view = {};
	int ret;

	if (upatch_is_unload(u))
		return -EINVAL;
	ret = btf_rodata_btf(u, &view);
	if (ret)
		goto out;
	ret = json ? print_rodata_json(u, path, &view) :
		    print_rodata_text(u, path, &view);
out:
	btf__free(view.btf);
	return ret;
}
