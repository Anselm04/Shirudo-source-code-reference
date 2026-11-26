// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * config_image_read_header() of util/config_image.c, the target's preflight
 * of a config image's dm-verity superblock, on every hash file of LEN bytes:
 * it accepts exactly the version 1 SHA-256 layout of 4096-byte blocks and
 * 32-byte salt over 1 to 2^28 data blocks, and returns the size of the
 * hash tree dm-verity reads for them.
 */

#define PROOF_FILE	LEN
#include "proof.h"
#include "../../../util/config_image.c"

static __u32 le32_at(size_t off)
{
	return get_le32(proof_file + off);
}

static bool superblock_valid(void)
{
	static const char signature[8] = "verity", sha256[32] = "sha256";

	return !memcmp(proof_file, signature, sizeof(signature)) &&
	       le32_at(8) == 1 &&
	       le32_at(12) == 1 && !memcmp(proof_file + 32, sha256, 32) &&
	       le32_at(64) == 4096 && le32_at(68) == 4096 &&
	       get_le16(proof_file + 80) == 32;
}

/* The superblock and the levels dm-verity's constructor lays out. */
static __u64 tree_blocks(__u64 n)
{
	__u64 total = 1;
	__u32 levels = 0, i;

	while ((n - 1) >> (7 * levels))
		levels++;
	for (i = 1; i <= levels; i++)
		total += (n + (1ull << (7 * i)) - 1) >> (7 * i);
	return total;
}

void harness(void)
{
	struct config_image image, was;
	__u64 blocks;
	size_t i;

	proof_file_open();
	was = image;
	if (config_image_read_header(3, &image)) {
		__CPROVER_assert(!memcmp(&image, &was, sizeof(image)),
				 "a refusal leaves the image as it was");
		return;
	}
	blocks = get_le64(proof_file + 72);
	__CPROVER_assert(superblock_valid(), "the one superblock layout");
	__CPROVER_assert(image.data_blocks == blocks && blocks &&
			 blocks <= 1u << 28, "1 to 2^28 data blocks");
	__CPROVER_assert(image.hash_blocks == tree_blocks(blocks),
			 "the hash tree dm-verity reads");
	for (i = 0; i < CONFIG_IMAGE_SALT_SIZE; i++)
		__CPROVER_assert(image.salt[i] == proof_file[88 + i],
				 "the salt it records");
}
