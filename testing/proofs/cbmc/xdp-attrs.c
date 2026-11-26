// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The netlink attribute parsers of util/xdp.c, which read the kernel's
 * replies about network devices, on every buffer of LEN bytes: an
 * attribute found lies inside the buffer with its header, a string is
 * NUL-terminated within its room and a number of its exact size, and a
 * device parsed has an index, a name, terminated strings and, with a
 * devlink port, its bus and device.
 */

/* util/string.c is included behind a file that includes its header. */
#define STRING_INTERNAL

#include "proof.h"
/* NLA_HDRLEN casts the negative ~(NLA_ALIGNTO - 1) on purpose. */
#pragma CPROVER check push
#pragma CPROVER check disable "conversion"
#include "../../../util/xdp.c"
#pragma CPROVER check pop
#include "../../../util/string.c"

#define ATTR_HEADER	sizeof(struct nlattr)

static size_t aligned(size_t n)
{
	return (n + 3) / 4 * 4;
}

/* The attributes a buffer of LEN bytes holds, each taking its aligned length. */
static bool attributes_end(const __u8 *data, size_t len, __u16 type,
			   size_t *found)
{
	size_t off = 0, seen = 0;

	while (off < len) {
		const struct nlattr *attr = (const void *)(data + off);

		if (len - off < ATTR_HEADER || attr->nla_len < ATTR_HEADER ||
		    attr->nla_len > len - off ||
		    aligned(attr->nla_len) > len - off)
			return false;
		if ((attr->nla_type & ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)) ==
		    type) {
			*found = off;
			seen++;
		}
		off += aligned(attr->nla_len);
	}
	return seen <= 1;
}

static void find(const __u8 *data)
{
	const struct nlattr *attr;
	size_t found = LEN;
	bool well_formed;
	__u16 type;
	int ret;

	ret = attr_find(data, LEN, type, &attr);
	well_formed = attributes_end(data, LEN, type, &found);
	__CPROVER_assert(!ret == well_formed,
			 "a run of whole attributes, the type at most once");
	if (ret)
		return;
	__CPROVER_assert(attr ? (const __u8 *)attr == data + found :
				found == LEN,
			 "the attribute of the type, or none");
}

static void string(const __u8 *data)
{
	char out[8];
	size_t cap, i;
	__u16 type;

	__CPROVER_assume(cap <= sizeof(out));
	for (i = 0; i < sizeof(out); i++)
		out[i] = 'x';
	if (attr_string(data, LEN, type, out, cap))
		return;
	for (i = 0; i < cap && out[i]; i++)
		;
	__CPROVER_assert(i < cap || out[0] == 'x',
			 "a string terminated within its room, or none");
}

static void number(const __u8 *data)
{
	const struct nlattr *attr;
	bool present = false;
	__u64 value = 0;
	size_t size;
	__u16 type;

	__CPROVER_assume(size == 2 || size == 4 || size == 8);
	if (attr_number(data, LEN, type, &value, size, &present))
		return;
	if (attr_find(data, LEN, type, &attr) || !attr) {
		__CPROVER_assert(!present && !value, "nothing without one");
		return;
	}
	__CPROVER_assert(present && attr->nla_len == ATTR_HEADER + size &&
			 !memcmp(&value, (const __u8 *)attr + ATTR_HEADER,
				 size),
			 "a number of exactly its size");
}

static bool terminated(const char *s, size_t cap)
{
	return memchr(s, '\0', cap);
}

static void device(const __u8 *data)
{
	struct xdp_device dev;

	if (xdp_device_parse(data, LEN, &dev))
		return;
	__CPROVER_assert(dev.ifindex > 0 && dev.name[0] &&
			 terminated(dev.name, sizeof(dev.name)),
			 "an index and a name");
	__CPROVER_assert(terminated(dev.kind, sizeof(dev.kind)) &&
			 terminated(dev.parent_bus, sizeof(dev.parent_bus)) &&
			 terminated(dev.devlink_bus, sizeof(dev.devlink_bus)) &&
			 terminated(dev.devlink_device,
				    sizeof(dev.devlink_device)),
			 "terminated strings");
	__CPROVER_assert(!dev.devlink_port ||
			 (dev.devlink_bus[0] && dev.devlink_device[0]),
			 "a devlink port with its bus and device");
}

void harness(void)
{
	const __u8 *data = any_bytes(LEN);

	find(data);
	string(data);
	number(data);
	device(data);
}
