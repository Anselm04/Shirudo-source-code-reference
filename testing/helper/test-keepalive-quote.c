// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Quotes a keepalive body file with the TPM as status --otel quotes its
 * own body, and prints the row of testing/fixtures/keepalive/quotes.tsv:
 * the file name, attest, sig, ak and body_sha256, tab-separated.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "crypto.h"
#include "hex.h"
#include "io.h"
#include "keepalive.h"
#include "keepalive_quote.h"
#include "malloc.h"

#define QUOTE_FIELDS	3

/* Turns the fields of attest=...;sig=...;ak=... into their values. */
static int quote_values(char *quote, const char *values[QUOTE_FIELDS])
{
	static const char *const keys[QUOTE_FIELDS] = {
		"attest=", "sig=", "ak=",
	};
	char *field = quote;
	size_t i;

	for (i = 0; i < QUOTE_FIELDS; i++) {
		char *end;

		values[i] = str_after_prefix(field, keys[i]);
		if (!values[i])
			return -EINVAL;
		end = strchr(field, ';');
		if (i + 1 == QUOTE_FIELDS) {
			if (end)
				return -EINVAL;
		} else {
			if (!end)
				return -EINVAL;
			*end = '\0';
			field = end + 1;
		}
	}
	return 0;
}

static int print_row(const char *path, const char *body, size_t len)
{
	char hash[2 * CRYPTO_SHA256_LEN + 1];
	char quote[KEEPALIVE_QUOTE_MAX];
	const char *values[QUOTE_FIELDS];
	__u8 digest[CRYPTO_SHA256_LEN];
	const char *name;
	int ret;

	ret = keepalive_quote(body, len, quote, sizeof(quote));
	if (ret) {
		fprintf(stderr, "quote %s: %s\n", path, strerror(-ret));
		return ret;
	}
	ret = quote_values(quote, values);
	if (ret) {
		fprintf(stderr, "quote %s: not attest=;sig=;ak=\n", path);
		return ret;
	}
	ret = sha256_buffer(body, len, digest);
	if (ret)
		return ret;
	hex_encode(digest, sizeof(digest), hash);
	name = strrchr(path, '/');
	name = name ? name + 1 : path;
	if (printf("%s\t%s\t%s\t%s\t%s\n", name, values[0], values[1],
		   values[2], hash) < 0 || fflush(stdout))
		return -EIO;
	return 0;
}

int main(int argc, char **argv)
{
	char *body = NULL;
	size_t len = 0;
	int ret;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <body>\n", argv[0]);
		return 2;
	}
	ret = read_file(argv[1], KEEPALIVE_BODY_MAX - 1, &body, &len);
	if (ret) {
		fprintf(stderr, "read %s: %s\n", argv[1], strerror(-ret));
		return 1;
	}
	ret = print_row(argv[1], body, len);
	xfree(body, len + 1);
	return ret ? 1 : 0;
}
