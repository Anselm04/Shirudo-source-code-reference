// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * obs_file.bpf.c -- opens of credential material and persistence files.
 *
 * Every open is matched by base name and parent directory against the
 * signed rule list; only a match pays for the path resolution and the
 * record, so the hook stays cheap on the open path.
 */

#define OBS_FILE_RULE_WRITE	(1u << 0)
#define OBS_FILE_RULE_ANY_NAME	(1u << 1)
#define OBS_FILE_RULE_DISABLED	(1u << 2)

#define FMODE_READ_BIT		0x1
#define FMODE_WRITE_BIT		0x2

struct obs_file_rule {
	char name[OBS_NAME_LEN];
	char parent[OBS_NAME_LEN];
	__u32 flags;
	__u32 _pad;
};

#include "file_watch_generated.h"

static const struct obs_file_rule obs_file_rules[OBS_FILE_WATCH_RULES] =
	OBS_FILE_WATCH_INIT;

struct file_key {
	struct obs_ident ident;
	__u32 euid;
	__u32 mode;
	char path[OBS_PATH_LEN];
};

struct file_val {
	__u64 count;
	__u64 first_ns;
	__u64 last_ns;
	__u32 pid;
	__u32 rule;
	__u64 magic;
};

#define OBS_T		file
#define OBS_T_MAP	file
#define OBS_T_KEY	struct file_key
#define OBS_T_VAL	struct file_val
#define OBS_T_CAPACITY	2048
#define OBS_T_BUCKETS	1024
#define OBS_T_STEPS	8
#define OBS_T_MAGIC	0x454c4946u	/* "FILE" little-endian */
#define OBS_T_RECORD	208
#define OBS_T_EMIT	file_emit_record
#include "obs_table.h"

static int file_emit_record(struct serial_chunk *chunk, __u32 off,
			    const struct file_entry __arena *e)
{
	*(__u32 *)&chunk->data[off + 8] = e->key.ident.exe.dev;
	*(__u32 *)&chunk->data[off + 12] = 0;
	*(__u64 *)&chunk->data[off + 16] = e->key.ident.exe.ino;
	*(__u64 *)&chunk->data[off + 24] = e->key.ident.cgroup;
	*(__u32 *)&chunk->data[off + 32] = e->key.euid;
	*(__u32 *)&chunk->data[off + 36] = e->key.mode;
	obs_emit_bytes(chunk, off + 40, e->key.path, OBS_PATH_LEN / 8);
	*(__u64 *)&chunk->data[off + 168] = e->val.count;
	*(__u64 *)&chunk->data[off + 176] = e->val.first_ns;
	*(__u64 *)&chunk->data[off + 184] = e->val.last_ns;
	*(__u32 *)&chunk->data[off + 192] = e->val.pid;
	*(__u32 *)&chunk->data[off + 196] = e->val.rule;
	*(__u64 *)&chunk->data[off + 200] = e->val.magic;
	return 0;
}

static __always_inline bool obs_rule_words_equal(const char *rule,
						 const char *buf)
{
	const __u64 *a = (const __u64 *)rule;
	const __u64 *b = (const __u64 *)buf;

	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

static __always_inline int obs_file_match(const char *name,
					  const char *parent, bool write)
{
	const struct obs_file_rule *rule;
	__u32 i;

#pragma clang loop unroll(disable)
	for (i = 0; i < OBS_FILE_WATCH_RULES; i++) {
		rule = &obs_file_rules[i];
		if (rule->flags & OBS_FILE_RULE_DISABLED)
			continue;
		if ((rule->flags & OBS_FILE_RULE_WRITE) && !write)
			continue;
		if (!(rule->flags & OBS_FILE_RULE_ANY_NAME) &&
		    !obs_rule_words_equal(rule->name, name))
			continue;
		if (rule->parent[0] &&
		    !obs_rule_words_equal(rule->parent, parent))
			continue;
		return (int)i;
	}
	return -1;
}

SEC("lsm.s/file_open")
int BPF_PROG(obs_file_open, struct file *filp)
{
	struct file_entry __arena *e;
	struct file_key key = {};
	char name[OBS_NAME_LEN] = {};
	char parent[OBS_NAME_LEN] = {};
	struct dentry *dentry, *pdentry;
	const unsigned char *src;
	__u64 now;
	__u32 fmode;
	bool write;
	int status;
	int rule;

	if (!filp)
		return 0;
	dentry = filp->f_path.dentry;
	if (!dentry)
		return 0;
	src = BPF_CORE_READ(dentry, d_name.name);
	if (!src || bpf_probe_read_kernel_str(name, sizeof(name), src) <= 0)
		return 0;
	pdentry = BPF_CORE_READ(dentry, d_parent);
	if (pdentry) {
		src = BPF_CORE_READ(pdentry, d_name.name);
		if (src)
			bpf_probe_read_kernel_str(parent, sizeof(parent), src);
	}
	fmode = BPF_CORE_READ(filp, f_mode);
	write = (fmode & FMODE_WRITE_BIT) != 0;
	rule = obs_file_match(name, parent, write);
	if (rule < 0)
		return 0;

	now = obs_now();
	obs_ident_checked(&key.ident, now);
	key.euid = obs_current_euid();
	key.mode = fmode & (FMODE_READ_BIT | FMODE_WRITE_BIT);
	if (bpf_d_path(&filp->f_path, key.path, sizeof(key.path)) <= 0) {
		/* A path too long leaves its tail in the key; the name alone is the key. */
		__builtin_memset(key.path, 0, sizeof(key.path));
		__builtin_memcpy(key.path, name, OBS_NAME_LEN);
	}

	e = file_touch(&key, &status);
	if (!e)
		return 0;
	if (status == OBS_TOUCH_CREATED) {
		e->val.first_ns = now;
		e->val.rule = (__u32)rule;
		e->val.magic = BPF_CORE_READ(filp, f_inode, i_sb, s_magic);
	}
	__sync_fetch_and_add(&e->val.count, 1);
	e->val.last_ns = now;
	e->val.pid = obs_tgid();
	return 0;
}
