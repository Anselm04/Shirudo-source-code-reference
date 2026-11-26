// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The certificates and detached CMS signatures that come with indexes,
 * tree publications, packages and keys: a 16-bit little-endian length, a
 * DER certificate of that length and a signature over the certificate.
 */

#include <stdlib.h>

#include "crypto.h"
#include "fuzz.h"
#include "keys.h"
#include "malloc.h"

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct cert_pubkey pub;
	struct cert cert = {};
	size_t der_len, sig_len, n;
	const __u8 *der, *sig;
	__u8 sha[32], fp[32];
	__u8 *raw;

	if (size < 2)
		return 0;
	der_len = data[0] | (size_t)data[1] << 8;
	if (der_len > size - 2)
		return 0;
	der = data + 2;
	sig = der + der_len;
	sig_len = size - 2 - der_len;

	keys_digest_der(der, der_len, sha, fp);
	if (!cert_read_der(der, der_len, &cert)) {
		int signed_by = cms_signed_by(sig, sig_len, &cert);

		/* A signature that verifies is one the certificate made. */
		if (!verify_detached(der, der_len, sig, sig_len, &cert) &&
		    signed_by != 1)
			abort();
		if (!cert_pubkey(&cert, &pub) && pub.n_len > sizeof(pub.n))
			abort();
		cert_free(&cert);
	}

	raw = xmalloc(sig_len + 1);
	if (raw) {
		/* Base64 never decodes to more bytes than it spans. */
		if (!base64_decode((const char *)sig, sig_len, raw,
				   sig_len + 1, &n) && n > sig_len)
			abort();
		xfree(raw, sig_len + 1);
	}
	return 0;
}
