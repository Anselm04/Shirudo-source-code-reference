/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The keepalive body, the status record a node's TPM quotes, and its
 * packed fields: the per-operation outcome mask and the conditions word.
 */

#ifndef SHIRUDO_KEEPALIVE_H
#define SHIRUDO_KEEPALIVE_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>

#include "bpf/lib/integrity.h"
#include "bpf/lib/tamper.h"
#include "bpm_tree.h"
#include "conditions.h"
#include "crypto.h"

#define KEEPALIVE_MASK_OPS	512
#define KEEPALIVE_MASK_BYTES	(KEEPALIVE_MASK_OPS / 4)
#define KEEPALIVE_MASK_B64_MAX	BASE64_SIZE(KEEPALIVE_MASK_BYTES)

/*
 * The body reports the last this many operations up to the head of the
 * tree, whatever segments hold them. A test build lowers it so that the
 * window of a short tree starts past seq 0, inside an older segment.
 */
#ifndef KEEPALIVE_WINDOW_OPS
#define KEEPALIVE_WINDOW_OPS	KEEPALIVE_MASK_OPS
#endif
BUILD_BUG_ON(KEEPALIVE_WINDOW_OPS < 1 ||
	     KEEPALIVE_WINDOW_OPS > KEEPALIVE_MASK_OPS);

/* Holds the largest body and its terminator. */
#define KEEPALIVE_BODY_MAX	4096

#define KEEPALIVE_REGISTER_REBOUND	(1u << 0)
#define KEEPALIVE_BOUND_LATE		(1u << 1)
#define KEEPALIVE_TREE_LOG_MISMATCH	(1u << 2)
#define KEEPALIVE_TAMPER_UNAVAILABLE	(1u << 3)
#define KEEPALIVE_TREE_OP_PENDING	(1u << 4)
#define KEEPALIVE_SNAPSHOT_UNSETTLED	(1u << 5)
#define KEEPALIVE_INTEGRITY_UNAVAILABLE	(1u << 6)

/*
 * How many times a snapshot reads the tree before it gives up on a state
 * that keeps moving; kept here alone so that system testing can tune it.
 */
#define KEEPALIVE_SNAPSHOT_TRIES	3

/*
 * A hash is 64 lowercase hex digits. A string that may be null is so when
 * it is NULL or, but for mask, empty, as sysinfo and the tree state leave
 * what is absent.
 */
struct keepalive_input {
	const char	*boot_id;
	const char	*version_id;		/* hash */
	const char	*config_root;		/* hash or null */
	const char	*kernel_release;
	const char	*image_id;		/* or null */
	const char	*image_version;		/* or null */
	const char	*image_root;		/* hash or null */
	const char	*verdict;
	__u16		cond;			/* keepalive_cond() */
	__u32		flags;
	const __u64	*tamper;		/* TAMPER_MAX counters or null */
	const __u64	*integrity;		/* INTEGRITY_MAX counters or null */
	/* Not set: the node follows no tree and the seven tree keys are null. */
	bool		tree;
	const char	*tree_id;
	__u64		generation;
	__u64		base_seq;
	__u64		last_seq;
	const char	*base_root;		/* hash or null */
	const char	*projection_root;	/* hash */
	/* From keepalive_mask(): NULL is null, "" a window of no operation. */
	const char	*mask;
	const char	*set_sha256;		/* hash */
	__u64		count;
	__u64		not_ok;
};

/*
 * Writes the body as one compact JSON object with its terminator and no
 * newline, and its length without the terminator in *len: the bytes to
 * hash, send and store. -ENOSPC when cap does not hold them, -EINVAL for
 * a string that is NULL where the body needs one or a hash that is not
 * one, -EILSEQ for a string that is not UTF-8; buf is then empty and
 * *len 0.
 */
int keepalive_emit(const struct keepalive_input *in, char *buf, size_t cap,
		   size_t *len) __must_check;

/*
 * The first code in the highest bits, as the backend reads them; -EINVAL
 * for a code past two bits or more than KEEPALIVE_MASK_OPS codes, -E2BIG
 * for a buffer too small.
 */
int keepalive_mask(const __u8 *codes, size_t n, char *b64,
		   size_t cap) __must_check;

/* Each pair by type name, so that a condition conditions() adds moves none. */
__u16 keepalive_cond(const struct condition *conds, size_t n);

/*
 * The reads of a snapshot. read_state() is tree_state_read() and
 * pending() whether pending.json exists. collect() reads what follows
 * the state it is given, the outcomes up to its last_seq and the loaded
 * set, into ctx, and fails the snapshot with a nonzero return.
 */
struct keepalive_snapshot_ops {
	int	(*read_state)(void *ctx, struct tree_state *state);
	bool	(*pending)(void *ctx);
	int	(*collect)(void *ctx, const struct tree_state *state,
			   int state_rc);
};

/*
 * Reads the tree keys and the loaded set of one point without the tree
 * lock, which a sync holds for minutes: the state, pending.json, what
 * collect() reads, pending.json and the state again, over again while
 * the second state differs from the first, at most
 * KEEPALIVE_SNAPSHOT_TRIES times. *state and *state_rc are the first
 * read of the last try. Sets KEEPALIVE_TREE_OP_PENDING in *flags when
 * that try saw pending.json and KEEPALIVE_SNAPSHOT_UNSETTLED when the
 * tries ran out. 0, or what collect() returned.
 */
int keepalive_snapshot(const struct keepalive_snapshot_ops *ops, void *ctx,
		       struct tree_state *state, int *state_rc,
		       __u32 *flags) __must_check;

#endif /* SHIRUDO_KEEPALIVE_H */
