// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * obs_dns.bpf.c -- map answered addresses to the names that resolved them.
 *
 * Egress UDP queries are keyed by network namespace, flow and transaction
 * id and remembered with the querying identity; the matching ingress
 * response consumes the entry and records every A and AAAA answer under
 * the identity and address.
 */

#define DNS_PORT		53
#define DNS_TYPE_A		1
#define DNS_TYPE_AAAA		28
#define DNS_MAX_NAMES_PER_IP	4
#define DNS_MAX_NAME_CHARS	255
#define DNS_NAME_BYTES		(DNS_MAX_NAME_CHARS + 1)
#define DNS_MAX_WIRE_NAME_BYTES	255
#define DNS_MAX_LABEL_BYTES	63
#define DNS_MAX_LABELS		127
#define DNS_MAX_NAME_STEPS	(DNS_MAX_LABELS + 1)
/* A 1232-byte UDP response can hold at most 75 minimal 16-byte A answers. */
#define DNS_MAX_ANSWERS		75
#define DNS_MAX_UDP_BYTES	1232
#define DNS_MAX_IP_HEADER_BYTES	60
#define DNS_MAX_PACKET_BYTES	(DNS_MAX_UDP_BYTES + DNS_MAX_IP_HEADER_BYTES)
#define DNS_REQ_MAP_ENTRIES	1024
#define DNS_COMPRESSED_MASK	0xc0
/* Set in what the label and name parsers return, above any label's length. */
#define DNS_NAME_REPLACED	0x100

enum dns_debug_counter {
	DNS_DBG_QUERY_PACKET,
	DNS_DBG_QUERY_NO_UID,
	DNS_DBG_QUERY_HDR_FAIL,
	DNS_DBG_QUERY_IS_RESPONSE,
	DNS_DBG_QUERY_QDCOUNT_BAD,
	DNS_DBG_QUERY_SCRATCH_MISS,
	DNS_DBG_QUERY_NAME_FAIL,
	DNS_DBG_QUERY_NAME_REPLACED,
	DNS_DBG_QUERY_EMPTY_NAME,
	DNS_DBG_QUERY_QTYPE_READ_FAIL,
	DNS_DBG_QUERY_QTYPE_UNSUPPORTED,
	DNS_DBG_QUERY_STORED,
	DNS_DBG_RESP_PACKET,
	DNS_DBG_RESP_HDR_FAIL,
	DNS_DBG_RESP_NOT_RESPONSE,
	DNS_DBG_RESP_QDCOUNT_BAD,
	DNS_DBG_RESP_NO_ANSWER,
	DNS_DBG_RESP_REQ_MISS,
	DNS_DBG_RESP_QNAME_SKIP_FAIL,
	DNS_DBG_RESP_QTYPE_READ_FAIL,
	DNS_DBG_RESP_QTYPE_MISMATCH,
	DNS_DBG_RESP_ANSWER_SEEN,
	DNS_DBG_RESP_ANSWER_SKIP_FAIL,
	DNS_DBG_RESP_RR_READ_FAIL,
	DNS_DBG_RESP_RDATA_BOUNDS_FAIL,
	DNS_DBG_RESP_ADDR_UNSUPPORTED,
	DNS_DBG_RESP_ADDR_PARSED,
	DNS_DBG_RESP_TOUCH,
	DNS_DBG_RESP_DELETE,
	DNS_DBG_TOUCH_CALLED,
	DNS_DBG_TOUCH_INIT_FAIL,
	DNS_DBG_TOUCH_HIT,
	DNS_DBG_ALLOC_ATTEMPT,
	DNS_DBG_ALLOC_BAD_IDX,
	DNS_DBG_ALLOC_OK,
	DNS_DBG_ALLOC_ENTRY_MISS,
	DNS_DBG_CAS_OK,
	DNS_DBG_CAS_FAIL,
	DNS_DBG_PACKET_IPV4,
	DNS_DBG_PACKET_IPV6,
	DNS_DBG_PACKET_NOT_UDP,
	DNS_DBG_PACKET_PORT_SKIP,
	DNS_DBG_MAX,
};

struct dns_key {
	struct obs_ident ident;
	__u8 family;
	__u8 _pad[7];
	__u32 addr[4];
};

struct dns_name {
	__u64 seen;
	__u64 last_ns;
	char name[DNS_NAME_BYTES];
};

struct dns_val {
	__u64 count;
	__u64 first_ns;
	__u64 last_ns;
	struct dns_name names[DNS_MAX_NAMES_PER_IP];
};

struct dns_request {
	struct obs_exe exe;
	__u64 cgroup;
	char name[DNS_NAME_BYTES];
	__u16 qtype;
	__u16 _pad;
	__u32 _pad2;
};

/*
 * Canonical client-to-resolver tuple.  Packet address and port bytes stay
 * in network order, so reversing an ingress response produces the query
 * key.
 */
struct dns_request_key {
	__u64 netns_cookie;
	__u32 client_addr[4];
	__u32 resolver_addr[4];
	__u16 id;
	__u16 client_port;
	__u16 resolver_port;
	__u8 family;
	__u8 _pad;
};

struct dns_scratch {
	struct dns_request req;
	/* Tailroom lets the verifier bound a full final-label direct copy. */
	char verifier_bounds[DNS_MAX_LABEL_BYTES];
};

struct dns_hdr {
	__u16 id;
	__u16 flags;
	__u16 qdcount;
	__u16 ancount;
	__u16 nscount;
	__u16 arcount;
};

BUILD_BUG_ON_MSG(sizeof(struct dns_request_key) != 48,
		 "dns request key ABI must remain verifier-friendly");
BUILD_BUG_ON_MSG(sizeof(struct dns_request) != 288,
		 "dns request value ABI is shared with the test helper");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, DNS_REQ_MAP_ENTRIES);
	__type(key, struct dns_request_key);
	__type(value, struct dns_request);
} obs_i_dns_req SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dns_scratch);
} obs_i_dns_tmp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, DNS_DBG_MAX);
	__type(key, __u32);
	__type(value, __u64);
} obs_i_dns_dbg SEC(".maps");

#define OBS_T		dns
#define OBS_T_MAP	dns
#define OBS_T_KEY	struct dns_key
#define OBS_T_VAL	struct dns_val
#define OBS_T_CAPACITY	1024
#define OBS_T_BUCKETS	512
#define OBS_T_STEPS	8
#define OBS_T_MAGIC	0x41534e44u	/* "DNSA" little-endian */
#define OBS_T_RECORD	1168
#define OBS_T_EMIT	dns_emit_record
#include "obs_table.h"

static __always_inline void dns_debug_inc(__u32 key)
{
	__u64 *value;

	if (key >= DNS_DBG_MAX)
		return;
	value = bpf_map_lookup_elem(&obs_i_dns_dbg, &key);
	if (value)
		__sync_fetch_and_add(value, 1);
}

__attribute__((noinline)) void
obs_dns_emit_name(struct serial_chunk *chunk, __u32 base,
		  const struct dns_name __arena *stat)
{
	int i;

	if (!chunk || !stat ||
	    base > SERIAL_CHUNK_PAYLOAD - sizeof(struct dns_name))
		return;
	barrier_var(base);
	*(__u64 *)&chunk->data[base] = stat->seen;
	*(__u64 *)&chunk->data[base + 8] = stat->last_ns;
#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_NAME_BYTES; i++)
		chunk->data[base + 16 + i] = stat->name[i];
}

static int dns_emit_record(struct serial_chunk *chunk, __u32 off,
			   const struct dns_entry __arena *e)
{
	int i;

	*(__u32 *)&chunk->data[off + 8] = e->key.ident.exe.dev;
	*(__u32 *)&chunk->data[off + 12] = 0;
	*(__u64 *)&chunk->data[off + 16] = e->key.ident.exe.ino;
	*(__u64 *)&chunk->data[off + 24] = e->key.ident.cgroup;
	chunk->data[off + 32] = e->key.family;
	chunk->data[off + 33] = 0;
	*(__u16 *)&chunk->data[off + 34] = 0;
	*(__u32 *)&chunk->data[off + 36] = 0;
	*(__u32 *)&chunk->data[off + 40] = e->key.addr[0];
	*(__u32 *)&chunk->data[off + 44] = e->key.addr[1];
	*(__u32 *)&chunk->data[off + 48] = e->key.addr[2];
	*(__u32 *)&chunk->data[off + 52] = e->key.addr[3];
	*(__u64 *)&chunk->data[off + 56] = e->val.count;
	*(__u64 *)&chunk->data[off + 64] = e->val.first_ns;
	*(__u64 *)&chunk->data[off + 72] = e->val.last_ns;
#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_NAMES_PER_IP; i++)
		obs_dns_emit_name(chunk, off + 80 + i * sizeof(struct dns_name),
				  &e->val.names[i]);
	return 0;
}

__attribute__((noinline)) bool
obs_dns_name_equal_arena(const char __arena *a, const struct dns_request *req)
{
	int i;

	if (!a || !req)
		return false;
#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_NAME_BYTES; i++) {
		char ca = a[i];
		char cb = req->name[i];

		if (ca != cb)
			return false;
		if (ca == '\0')
			return true;
	}
	return true;
}

__attribute__((noinline)) void
obs_dns_name_copy_to_arena(char __arena *dst, const struct dns_request *req)
{
	int i;

	if (!dst || !req)
		return;
#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_NAME_CHARS; i++)
		dst[i] = req->name[i];
	dst[DNS_MAX_NAME_CHARS] = 0;
}

static __always_inline void dns_name_set(struct dns_name __arena *stat,
					 const struct dns_request *req,
					 __u64 now)
{
	stat->seen = 1;
	stat->last_ns = now;
	obs_dns_name_copy_to_arena(stat->name, req);
}

/* Up to four names per address; the oldest gives way to a new one. */
static __always_inline void dns_names_touch(struct dns_entry __arena *e,
					    const struct dns_request *req,
					    __u64 now)
{
	struct dns_name __arena *stat, *oldest_stat = 0, *empty_stat = 0;
	__u64 oldest = ~0ULL;
	int i;

#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_NAMES_PER_IP; i++) {
		stat = &e->val.names[i];
		if (stat->seen && obs_dns_name_equal_arena(stat->name, req)) {
			__sync_fetch_and_add(&stat->seen, 1);
			stat->last_ns = now;
			return;
		}
		if (!stat->seen && !empty_stat)
			empty_stat = stat;
		if (stat->last_ns < oldest) {
			oldest = stat->last_ns;
			oldest_stat = stat;
		}
	}
	stat = empty_stat ? empty_stat : oldest_stat;
	if (stat)
		dns_name_set(stat, req, now);
}

static __always_inline void dns_table_touch(const struct dns_request *req,
					    const struct dns_key *ip,
					    __u64 now)
{
	struct dns_entry __arena *e;
	struct dns_key key = *ip;
	int status;

	if (!req->name[0])
		return;
	dns_debug_inc(DNS_DBG_TOUCH_CALLED);
	key.ident.exe = req->exe;
	key.ident.cgroup = req->cgroup;
	e = dns_touch(&key, &status);
	switch (status) {
	case OBS_TOUCH_HIT:
		dns_debug_inc(DNS_DBG_TOUCH_HIT);
		break;
	case OBS_TOUCH_CREATED:
		dns_debug_inc(DNS_DBG_ALLOC_ATTEMPT);
		dns_debug_inc(DNS_DBG_ALLOC_OK);
		dns_debug_inc(DNS_DBG_CAS_OK);
		break;
	case OBS_TOUCH_NO_STATE:
		dns_debug_inc(DNS_DBG_TOUCH_INIT_FAIL);
		return;
	case OBS_TOUCH_OVERFLOW:
		dns_debug_inc(DNS_DBG_ALLOC_ATTEMPT);
		dns_debug_inc(DNS_DBG_ALLOC_BAD_IDX);
		return;
	default:
		dns_debug_inc(DNS_DBG_ALLOC_ATTEMPT);
		dns_debug_inc(DNS_DBG_ALLOC_OK);
		dns_debug_inc(DNS_DBG_CAS_FAIL);
		return;
	}
	if (!e) {
		dns_debug_inc(DNS_DBG_ALLOC_ENTRY_MISS);
		return;
	}
	if (status == OBS_TOUCH_CREATED)
		e->val.first_ns = now;
	__sync_fetch_and_add(&e->val.count, 1);
	e->val.last_ns = now;
	dns_names_touch(e, req, now);
}

/*
 * Inlined, off comes from a caller's int that clang knows to be positive,
 * and clang 23 then tests it as signed 32-bit and sign-extends it, which
 * the verifier cannot bound. The barrier keeps it the __u32 it is.
 */
static __always_inline bool dns_read_u16(struct __sk_buff *skb, __u32 off,
					 __u16 *value)
{
	const __u8 *data = (const __u8 *)(long)skb->data;
	const __u8 *data_end = (const __u8 *)(long)skb->data_end;
	const __u8 *src;

	barrier_var(off);
	if (!value || off > DNS_MAX_PACKET_BYTES - sizeof(*value))
		return false;
	src = data + off;
	if (src + sizeof(*value) > data_end)
		return false;
	*value = ((__u16)src[0] << 8) | (__u16)src[1];
	return true;
}

static __always_inline bool dns_read_u32_raw(struct __sk_buff *skb,
					     __u32 off, __u32 *value)
{
	const __u8 *data = (const __u8 *)(long)skb->data;
	const __u8 *data_end = (const __u8 *)(long)skb->data_end;
	const __u8 *src;
	__u8 *dst = (__u8 *)value;

	barrier_var(off);
	if (!value || off > DNS_MAX_PACKET_BYTES - sizeof(*value))
		return false;
	src = data + off;
	if (src + sizeof(*value) > data_end)
		return false;
	dst[0] = src[0];
	dst[1] = src[1];
	dst[2] = src[2];
	dst[3] = src[3];
	return true;
}

/*
 * A label may hold any byte, but the recorded name is a C string with dots
 * between its labels: a NUL in a label would end the name there and a dot
 * would split the label in two, either recording another name than the
 * one resolved. Such a byte is recorded as '?', as is any other outside
 * printable ASCII, rather than the name refused, which would leave the
 * query unrecorded.
 */
static __always_inline bool dns_label_byte_recordable(__u8 byte)
{
	return byte > ' ' && byte <= '~' && byte != '.';
}

/*
 * Copies one label into the scratch name and returns the bytes it took,
 * 0 at the root label, with DNS_NAME_REPLACED set when a byte of the label
 * was recorded as '?'.
 */
__attribute__((noinline)) int
obs_dns_parse_name_label(struct __sk_buff *skb, __u32 off, __u32 start)
{
	__u8 *data = (__u8 *)(long)skb->data;
	__u8 *data_end = (__u8 *)(long)skb->data_end;
	__u32 wire_offset, dst, i, zero = 0;
	struct dns_scratch *scratch;
	int replaced = 0;
	__u8 len, byte;
	__u8 *src;
	char *out;

	if (off < start || off >= DNS_MAX_PACKET_BYTES)
		return -EINVAL;
	wire_offset = off - start;
	if (wire_offset >= DNS_MAX_WIRE_NAME_BYTES)
		return -EINVAL;

	src = data + off;
	if (src + 1 > data_end)
		return -EINVAL;
	len = *src;
	if (len & DNS_COMPRESSED_MASK)
		return -EINVAL;
	src++;

	scratch = bpf_map_lookup_elem(&obs_i_dns_tmp, &zero);
	if (!scratch)
		return -EINVAL;
	out = scratch->req.name;

	if (len == 0) {
		dst = wire_offset ? wire_offset - 1 : 0;
		if (dst >= DNS_MAX_NAME_CHARS)
			return -EINVAL;
		out[dst] = 0;
		return 0;
	}
	if (len > DNS_MAX_LABEL_BYTES)
		return -EINVAL;

	dst = wire_offset;
	if (dst >= DNS_MAX_NAME_CHARS)
		return -EINVAL;
	if (dst)
		out[dst - 1] = '.';
	if (len > DNS_MAX_NAME_CHARS - dst)
		return -EINVAL;

	/* The verifier needs the packet bound checked for each direct read. */
#pragma clang loop unroll(disable)
	for (i = 0; i < len; i++) {
		if (src + i + 1 > data_end)
			return -EINVAL;
		byte = src[i];
		if (!dns_label_byte_recordable(byte)) {
			byte = '?';
			replaced = DNS_NAME_REPLACED;
		}
		out[dst + i] = byte;
	}
	return ((int)len + 1) | replaced;
}

/*
 * Returns a negative errno, or 0 with DNS_NAME_REPLACED set when a byte of
 * the name was recorded as '?'.
 */
static __always_inline int dns_parse_name(struct __sk_buff *skb, __u32 off,
					  struct dns_request *req,
					  __u32 *next_off)
{
	__u32 start = off, pos = off;
	int consumed, replaced = 0, i;

	if (!req || !next_off)
		return -EINVAL;
	/*
	 * The request is stored whole, and its name goes on to the arena and
	 * the export: the bytes a longer name of an earlier query left behind
	 * the terminator would go with it.
	 */
	__builtin_memset(req->name, 0, sizeof(req->name));
#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_NAME_STEPS; i++) {
		consumed = obs_dns_parse_name_label(skb, pos, start);
		if (consumed < 0)
			return consumed;
		if (consumed == 0) {
			*next_off = pos + 1;
			return replaced;
		}
		replaced |= consumed & DNS_NAME_REPLACED;
		consumed &= ~DNS_NAME_REPLACED;
		if ((__u32)consumed > DNS_MAX_PACKET_BYTES - pos)
			return -EINVAL;
		pos += (__u32)consumed;
		if (pos - start >= DNS_MAX_WIRE_NAME_BYTES)
			return -EINVAL;
	}
	return -EINVAL;
}

static __always_inline int dns_skip_name(struct __sk_buff *skb, __u32 off,
					 __u32 *next_off)
{
	const __u8 *data = (const __u8 *)(long)skb->data;
	const __u8 *data_end = (const __u8 *)(long)skb->data_end;
	const __u8 *src;
	__u32 consumed = 0, label_len, pos;
	__u8 len;
	int i;

	if (!next_off || off >= DNS_MAX_PACKET_BYTES)
		return -EINVAL;
#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_NAME_STEPS; i++) {
		if (consumed >= DNS_MAX_WIRE_NAME_BYTES)
			return -EINVAL;
		if (consumed >= DNS_MAX_PACKET_BYTES - off)
			return -EINVAL;
		pos = off + consumed;
		src = data + pos;
		if (src + 1 > data_end)
			return -EINVAL;
		len = *src;

		if ((len & DNS_COMPRESSED_MASK) == DNS_COMPRESSED_MASK) {
			if (consumed + 2 < consumed ||
			    consumed + 2 > DNS_MAX_WIRE_NAME_BYTES)
				return -EINVAL;
			if (pos > DNS_MAX_PACKET_BYTES - 2)
				return -EINVAL;
			if (src + 2 > data_end)
				return -EINVAL;
			*next_off = off + consumed + 2;
			return 0;
		}
		if (len & DNS_COMPRESSED_MASK)
			return -EINVAL;

		consumed++;
		if (len == 0) {
			*next_off = off + consumed;
			return 0;
		}
		if (len > DNS_MAX_LABEL_BYTES)
			return -EINVAL;

		label_len = (__u32)len;
		if (consumed + label_len < consumed ||
		    consumed + label_len >= DNS_MAX_WIRE_NAME_BYTES)
			return -EINVAL;
		if (label_len > DNS_MAX_PACKET_BYTES - pos - 1)
			return -EINVAL;
		if (src + 1 + label_len > data_end)
			return -EINVAL;
		consumed += label_len;
	}
	return -EINVAL;
}

/* The querying identity: the socket's owner, else the sending task. */
static __always_inline bool dns_query_ident(struct __sk_buff *skb,
					    struct obs_ident *ident)
{
	struct obs_sock_meta *meta = 0;
	struct bpf_sock *sk = skb->sk;

	if (sk)
		meta = bpf_sk_storage_get(&obs_i_sock, sk, 0, 0);
	if (meta) {
		ident->exe = meta->exe;
		ident->cgroup = meta->cgroup;
		return true;
	}
	return obs_ident_checked(ident, obs_now());
}

/*
 * The scratch is per CPU and unguarded: kernel-obs is written for a kernel
 * without preemptible RCU, where no egress run starts on a CPU before
 * another one there ends.
 */
static __always_inline void dns_parse_query_payload(struct __sk_buff *skb,
						    __u32 dns_off,
						    struct dns_request_key *req_key)
{
	struct dns_scratch *scratch;
	struct obs_ident ident = {};
	__u32 zero = 0, next = 0;
	__u16 id, flags, qdcount, qtype, qclass;
	int parsed;

	dns_debug_inc(DNS_DBG_QUERY_PACKET);
	if (!dns_query_ident(skb, &ident)) {
		dns_debug_inc(DNS_DBG_QUERY_NO_UID);
		return;
	}
	if (!dns_read_u16(skb, dns_off, &id) ||
	    !dns_read_u16(skb, dns_off + 2, &flags) ||
	    !dns_read_u16(skb, dns_off + 4, &qdcount)) {
		dns_debug_inc(DNS_DBG_QUERY_HDR_FAIL);
		return;
	}
	if (flags & 0x8000) {
		dns_debug_inc(DNS_DBG_QUERY_IS_RESPONSE);
		return;
	}
	if (qdcount != 1) {
		dns_debug_inc(DNS_DBG_QUERY_QDCOUNT_BAD);
		return;
	}
	scratch = bpf_map_lookup_elem(&obs_i_dns_tmp, &zero);
	if (!scratch) {
		dns_debug_inc(DNS_DBG_QUERY_SCRATCH_MISS);
		return;
	}
	parsed = dns_parse_name(skb, dns_off + sizeof(struct dns_hdr),
				&scratch->req, &next);
	if (parsed < 0) {
		dns_debug_inc(DNS_DBG_QUERY_NAME_FAIL);
		return;
	}
	if (parsed & DNS_NAME_REPLACED)
		dns_debug_inc(DNS_DBG_QUERY_NAME_REPLACED);
	if (!scratch->req.name[0]) {
		dns_debug_inc(DNS_DBG_QUERY_EMPTY_NAME);
		return;
	}
	if (!dns_read_u16(skb, next, &qtype) ||
	    !dns_read_u16(skb, next + 2, &qclass)) {
		dns_debug_inc(DNS_DBG_QUERY_QTYPE_READ_FAIL);
		return;
	}
	if (qtype != DNS_TYPE_A && qtype != DNS_TYPE_AAAA) {
		dns_debug_inc(DNS_DBG_QUERY_QTYPE_UNSUPPORTED);
		return;
	}
	scratch->req.exe = ident.exe;
	scratch->req.cgroup = ident.cgroup;
	scratch->req.qtype = qtype;
	scratch->req._pad = 0;
	scratch->req._pad2 = 0;
	req_key->id = id;
	bpf_map_update_elem(&obs_i_dns_req, req_key, &scratch->req, BPF_ANY);
	dns_debug_inc(DNS_DBG_QUERY_STORED);
}

static __always_inline bool dns_answer_key(struct __sk_buff *skb,
					   __u32 rdata_off, __u16 rtype,
					   __u16 rdlen, struct dns_key *key)
{
	__builtin_memset(key, 0, sizeof(*key));
	if (rtype == DNS_TYPE_A) {
		if (rdlen != 4) {
			dns_debug_inc(DNS_DBG_RESP_ADDR_UNSUPPORTED);
			return false;
		}
		key->family = AF_INET;
		if (!dns_read_u32_raw(skb, rdata_off, &key->addr[0]))
			return false;
		dns_debug_inc(DNS_DBG_RESP_ADDR_PARSED);
		return true;
	}
	if (rtype == DNS_TYPE_AAAA) {
		if (rdlen != 16) {
			dns_debug_inc(DNS_DBG_RESP_ADDR_UNSUPPORTED);
			return false;
		}
		key->family = AF_INET6;
		if (!dns_read_u32_raw(skb, rdata_off, &key->addr[0]) ||
		    !dns_read_u32_raw(skb, rdata_off + 4, &key->addr[1]) ||
		    !dns_read_u32_raw(skb, rdata_off + 8, &key->addr[2]) ||
		    !dns_read_u32_raw(skb, rdata_off + 12, &key->addr[3]))
			return false;
		dns_debug_inc(DNS_DBG_RESP_ADDR_PARSED);
		return true;
	}
	dns_debug_inc(DNS_DBG_RESP_ADDR_UNSUPPORTED);
	return false;
}

__attribute__((noinline)) int
obs_dns_parse_answer(struct __sk_buff *skb, const struct dns_request *req,
		     __u32 off, __u64 now)
{
	struct dns_key key = {};
	__u32 next = 0, rdata_off;
	__u16 rtype, rdlen;

	if (!req)
		return -EINVAL;
	dns_debug_inc(DNS_DBG_RESP_ANSWER_SEEN);
	if (dns_skip_name(skb, off, &next)) {
		dns_debug_inc(DNS_DBG_RESP_ANSWER_SKIP_FAIL);
		return -EINVAL;
	}
	if (!dns_read_u16(skb, next, &rtype) ||
	    !dns_read_u16(skb, next + 8, &rdlen)) {
		dns_debug_inc(DNS_DBG_RESP_RR_READ_FAIL);
		return -EINVAL;
	}
	rdata_off = next + 10;
	barrier_var(rtype);
	barrier_var(rdlen);
	barrier_var(rdata_off);
	if (rdata_off > DNS_MAX_PACKET_BYTES ||
	    rdlen > DNS_MAX_PACKET_BYTES ||
	    rdata_off + rdlen < rdata_off ||
	    rdata_off + rdlen > DNS_MAX_PACKET_BYTES) {
		dns_debug_inc(DNS_DBG_RESP_RDATA_BOUNDS_FAIL);
		return -EINVAL;
	}
	if (dns_answer_key(skb, rdata_off, rtype, rdlen, &key)) {
		dns_debug_inc(DNS_DBG_RESP_TOUCH);
		dns_table_touch(req, &key, now);
	}
	return (int)(rdata_off + rdlen);
}

static __always_inline void dns_parse_response_payload(struct __sk_buff *skb,
						       __u32 dns_off,
						       struct dns_request_key *req_key)
{
	struct dns_request *req;
	__u64 now = obs_now();
	__u32 off, next = 0;
	__u16 id, flags, qdcount, ancount, qtype, qclass;
	int answer_off, i;

	dns_debug_inc(DNS_DBG_RESP_PACKET);
	if (!dns_read_u16(skb, dns_off, &id) ||
	    !dns_read_u16(skb, dns_off + 2, &flags) ||
	    !dns_read_u16(skb, dns_off + 4, &qdcount) ||
	    !dns_read_u16(skb, dns_off + 6, &ancount)) {
		dns_debug_inc(DNS_DBG_RESP_HDR_FAIL);
		return;
	}
	if ((flags & 0x8000) == 0) {
		dns_debug_inc(DNS_DBG_RESP_NOT_RESPONSE);
		return;
	}
	if (qdcount != 1) {
		dns_debug_inc(DNS_DBG_RESP_QDCOUNT_BAD);
		return;
	}
	if (ancount == 0) {
		dns_debug_inc(DNS_DBG_RESP_NO_ANSWER);
		return;
	}
	req_key->id = id;
	req = bpf_map_lookup_elem(&obs_i_dns_req, req_key);
	if (!req) {
		dns_debug_inc(DNS_DBG_RESP_REQ_MISS);
		return;
	}
	if (dns_skip_name(skb, dns_off + sizeof(struct dns_hdr), &next)) {
		dns_debug_inc(DNS_DBG_RESP_QNAME_SKIP_FAIL);
		bpf_map_delete_elem(&obs_i_dns_req, req_key);
		return;
	}
	if (!dns_read_u16(skb, next, &qtype) ||
	    !dns_read_u16(skb, next + 2, &qclass)) {
		dns_debug_inc(DNS_DBG_RESP_QTYPE_READ_FAIL);
		bpf_map_delete_elem(&obs_i_dns_req, req_key);
		return;
	}
	if (qtype != req->qtype) {
		dns_debug_inc(DNS_DBG_RESP_QTYPE_MISMATCH);
		bpf_map_delete_elem(&obs_i_dns_req, req_key);
		return;
	}

	off = next + 4;
#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_ANSWERS; i++) {
		if (i >= ancount)
			break;
		answer_off = obs_dns_parse_answer(skb, req, off, now);
		if (answer_off < 0)
			break;
		off = (__u32)answer_off;
	}
	bpf_map_delete_elem(&obs_i_dns_req, req_key);
	dns_debug_inc(DNS_DBG_RESP_DELETE);
}

/*
 * Called for every packet the cgroup hooks see, parsed or not, so the
 * debug counters account for the ones the header parser rejected.
 */
static __always_inline void dns_parse_packet(struct __sk_buff *skb,
					     const struct obs_pkt *pkt,
					     bool parsed, bool send)
{
	struct dns_request_key req_key = {};
	const __u32 *client, *resolver;
	__u32 dns_off;

	switch (pkt->ethertype) {
	case ETH_P_IP:
		dns_debug_inc(DNS_DBG_PACKET_IPV4);
		break;
	case ETH_P_IPV6:
		if (!obs_ipv6_enabled())
			return;
		dns_debug_inc(DNS_DBG_PACKET_IPV6);
		break;
	default:
		return;
	}
	if (!parsed)
		return;
	if (pkt->proto != IPPROTO_UDP) {
		dns_debug_inc(DNS_DBG_PACKET_NOT_UDP);
		return;
	}
	if (send) {
		if (pkt->dport != bpf_htons(DNS_PORT)) {
			dns_debug_inc(DNS_DBG_PACKET_PORT_SKIP);
			return;
		}
		client = pkt->saddr;
		resolver = pkt->daddr;
		req_key.client_port = pkt->sport;
		req_key.resolver_port = pkt->dport;
	} else {
		if (pkt->sport != bpf_htons(DNS_PORT)) {
			dns_debug_inc(DNS_DBG_PACKET_PORT_SKIP);
			return;
		}
		client = pkt->daddr;
		resolver = pkt->saddr;
		req_key.client_port = pkt->dport;
		req_key.resolver_port = pkt->sport;
	}
	req_key.family = pkt->family;
	req_key.client_addr[0] = client[0];
	req_key.client_addr[1] = client[1];
	req_key.client_addr[2] = client[2];
	req_key.client_addr[3] = client[3];
	req_key.resolver_addr[0] = resolver[0];
	req_key.resolver_addr[1] = resolver[1];
	req_key.resolver_addr[2] = resolver[2];
	req_key.resolver_addr[3] = resolver[3];
	req_key.netns_cookie = bpf_get_netns_cookie(skb);
	dns_off = (__u32)pkt->l4_off + sizeof(struct udphdr);
	if (send)
		dns_parse_query_payload(skb, dns_off, &req_key);
	else
		dns_parse_response_payload(skb, dns_off, &req_key);
}
