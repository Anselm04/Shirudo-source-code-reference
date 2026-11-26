// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/byteorder.h>
#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config_image.h"
#include "hex.h"

#define VERITY_DIGESTS_PER_BLOCK (CONFIG_IMAGE_BLOCK_SIZE / 32)

/* The standard veritysetup superblock occupies the first 512 bytes. */
struct verity_superblock {
	__u8 magic[8];
	__le32 version;
	__le32 hash_type;
	__u8 uuid[16];
	char algorithm[32];
	__le32 data_block_size;
	__le32 hash_block_size;
	__le64 data_blocks;
	__le16 salt_size;
	__u8 reserved[6];
	__u8 salt[256];
	__u8 padding[168];
};

BUILD_BUG_ON(sizeof(struct verity_superblock) != 512);

static int verity_hash_blocks(__u64 data_blocks, __u64 *out)
{
	__u64 total = 1;

	if (!data_blocks || data_blocks > CONFIG_IMAGE_MAX_BYTES /
					CONFIG_IMAGE_BLOCK_SIZE)
		return -EFBIG;
	while (data_blocks > 1) {
		data_blocks = DIV_ROUND_UP(data_blocks,
					   VERITY_DIGESTS_PER_BLOCK);
		total += data_blocks;
	}
	*out = total;
	return 0;
}

static int regular_file_size(int fd, __u64 *size)
{
	struct stat st;

	*size = 0;
	if (fstat(fd, &st))
		return -errno;
	if (!S_ISREG(st.st_mode) || st.st_size < 0)
		return -EINVAL;
	*size = st.st_size;
	return 0;
}

static int read_exact_at_start(int fd, void *buffer, size_t size)
{
	size_t done = 0;
	ssize_t n;

	while (done < size) {
		n = pread(fd, (__u8 *)buffer + done, size - done, done);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!n)
			return -EIO;
		done += n;
	}
	return 0;
}

static int validate_superblock(const struct verity_superblock *header)
{
	static const __u8 magic[8] = "verity";
	static const char algorithm[32] = "sha256";

	if (memcmp(header->magic, magic, sizeof(magic)) ||
	    le32_to_cpu(header->version) != 1 ||
	    le32_to_cpu(header->hash_type) != 1 ||
	    memcmp(header->algorithm, algorithm, sizeof(algorithm)) ||
	    le32_to_cpu(header->data_block_size) !=
		CONFIG_IMAGE_BLOCK_SIZE ||
	    le32_to_cpu(header->hash_block_size) !=
		CONFIG_IMAGE_BLOCK_SIZE ||
	    le16_to_cpu(header->salt_size) != CONFIG_IMAGE_SALT_SIZE)
		return -EINVAL;
	return 0;
}

int config_image_read_header(int hash_fd,
			     struct config_image *out)
{
	struct config_image image = {};
	struct verity_superblock header;
	int ret;

	if (!out)
		return -EINVAL;
	ret = read_exact_at_start(hash_fd, &header, sizeof(header));
	if (!ret)
		ret = validate_superblock(&header);
	if (ret)
		return ret;
	image.data_blocks = le64_to_cpu(header.data_blocks);
	ret = verity_hash_blocks(image.data_blocks, &image.hash_blocks);
	if (ret)
		return ret;
	memcpy(image.salt, header.salt, sizeof(image.salt));
	*out = image;
	return 0;
}

int config_image_check_files(int data_fd, int hash_fd,
			     const struct config_image *image)
{
	__u64 data_size, hash_size, blocks;
	int ret;

	if (!image)
		return -EINVAL;
	ret = verity_hash_blocks(image->data_blocks, &blocks);
	if (ret)
		return ret;
	if (blocks != image->hash_blocks)
		return -EINVAL;
	ret = regular_file_size(data_fd, &data_size);
	if (!ret)
		ret = regular_file_size(hash_fd, &hash_size);
	if (ret)
		return ret;
	if (data_size != image->data_blocks * CONFIG_IMAGE_BLOCK_SIZE ||
	    hash_size != image->hash_blocks * CONFIG_IMAGE_BLOCK_SIZE)
		return -EINVAL;
	return 0;
}

static int open_part(const char *prefix, const char *suffix)
{
	char path[PATH_MAX];
	int fd;

	if (strsprintf(path, sizeof(path), "%s%s", prefix, suffix) < 0)
		return -ENAMETOOLONG;
	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
	return fd < 0 ? -errno : fd;
}

static int read_root(const char *prefix, __u8 root[32])
{
	char text[65] = {};
	__u64 size;
	int fd, ret;

	fd = open_part(prefix, ".roothash");
	if (fd < 0)
		return fd;
	ret = regular_file_size(fd, &size);
	if (!ret && size != 64)
		ret = -EINVAL;
	if (!ret)
		ret = read_exact_at_start(fd, text, 64);
	close(fd);
	if (ret)
		return ret;
	if (!hex_is_lower(text, 64))
		return -EINVAL;
	return hex_decode(text, root, 32);
}

void config_image_close(struct config_image_open *image)
{
	if (!image)
		return;
	if (image->data_fd >= 0)
		close(image->data_fd);
	if (image->hash_fd >= 0)
		close(image->hash_fd);
	if (image->signature_fd >= 0)
		close(image->signature_fd);
	image->data_fd = -1;
	image->hash_fd = -1;
	image->signature_fd = -1;
}

static int open_image(const char *prefix, const __u8 *expected_root,
		      struct config_image_open *out)
{
	struct config_image_open image = {
		.data_fd = -1, .hash_fd = -1, .signature_fd = -1,
	};
	__u64 size;
	int ret;

	if (!prefix || !*prefix || !out)
		return -EINVAL;
	*out = image;
	image.data_fd = open_part(prefix, ".img");
	if (image.data_fd < 0)
		return image.data_fd;
	image.hash_fd = open_part(prefix, ".verity");
	if (image.hash_fd < 0) {
		ret = image.hash_fd;
		goto out;
	}
	ret = config_image_read_header(image.hash_fd,
				       &image.image);
	if (!ret)
		ret = read_root(prefix, image.image.root_hash);
	if (!ret)
		ret = config_image_check_files(image.data_fd,
					       image.hash_fd,
					       &image.image);
	if (ret)
		goto out;
	if (expected_root) {
		if (memcmp(expected_root, image.image.root_hash, 32))
			ret = -EKEYREJECTED;
	} else {
		image.image.signed_root = true;
		image.signature_fd = open_part(prefix, ".p7s");
		ret = image.signature_fd < 0 ? image.signature_fd :
			regular_file_size(image.signature_fd, &size);
		if (!ret && (!size || size > CONFIG_IMAGE_SIG_MAX))
			ret = -EINVAL;
	}
out:
	if (ret)
		config_image_close(&image);
	else
		*out = image;
	return ret;
}

int config_image_open(const char *prefix,
		      struct config_image_open *out)
{
	return open_image(prefix, NULL, out);
}

int config_image_open_root(const char *prefix,
			   const __u8 expected_root[32],
			   struct config_image_open *out)
{
	return expected_root ? open_image(prefix, expected_root, out) : -EINVAL;
}
