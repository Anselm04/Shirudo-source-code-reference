/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * One row of shirudo-quote-check: a keepalive quote and the SHA-256 of
 * the body it must cover, checked without a TPM, a key list or state.
 */

#ifndef SHIRUDO_QUOTE_CHECK_ROW_H
#define SHIRUDO_QUOTE_CHECK_ROW_H

#include <stddef.h>

#include <shirudo/misc.h>

#include "crypto.h"
#include "tpm.h"

#define QUOTE_BODY_HEX_LEN	(2 * TPM_DIGEST_LEN)
/* attest, sig, ak and body_sha256 with the three tabs between them. */
#define QUOTE_ROW_MAX							\
	(BASE64_LEN(TPM_ATTEST_MAX) + BASE64_LEN(TPM_SIGNATURE_MAX) +	\
	 BASE64_LEN(TPM_PUBLIC_MAX) + QUOTE_BODY_HEX_LEN + 3)
#define QUOTE_LINE_MAX		1024

enum quote_verdict {
	QUOTE_OK,
	QUOTE_BAD_SIGNATURE,
	QUOTE_BODY_MISMATCH,
	QUOTE_MALFORMED,
};

/* What follows the verdict describes a QUOTE_OK row alone. */
struct quote_result {
	enum quote_verdict	verdict;
	__u8			ak_name[TPM_NAME_LEN];
	__u8			ak_public[TPM_PUBLIC_MAX];
	size_t			ak_public_len;
	__u32			reset_count;
	__u64			clock;
};

/*
 * The len bytes at row are one TabSeparated row without its newline.
 * 0 with the verdict in *res, whatever the row holds, or a negative
 * errno when the check itself could not run and there is no verdict.
 */
int quote_row_check(const char *row, size_t len,
		    struct quote_result *res) __must_check;

/*
 * The verdict as its JSON object, without a newline, in the cap bytes at
 * line; QUOTE_LINE_MAX holds any of them. 0 or a negative errno.
 */
int quote_row_emit(const struct quote_result *res,
		   char *line, size_t cap) __must_check;

#endif /* SHIRUDO_QUOTE_CHECK_ROW_H */
