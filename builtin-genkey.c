// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Generate the shirudo X.509 self-signed signing cert.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "builtin.h"
#include "util/help.h"
#include "util/identity.h"
#include "util/log.h"
#include "util/options.h"
#include "util/crypto.h"
#include "util/paths.h"
#include "util/seal.h"

#define CERT_CN		"shirudo"
#define CERT_NO_EXPIRY	"99991231235959Z"

/*
 * ML-DSA-87 (FIPS 204, NIST category 5) is the only key type: the
 * kernel verifies it natively (CONFIG_CRYPTO_MLDSA) and the largest
 * parameter set gives a fleet-wide trust anchor that must outlive
 * hardware generations the most margin for about 2 KiB per signature.
 * Neither the smaller sets nor a classical algorithm are offered.
 */
#define GENKEY_ALG	"ML-DSA-87"

static int ensure_keys_dir(const char *keys_dir)
{
	int ret;

	if (!strcmp(keys_dir, "/")) {
		pr_err("keys dir cannot be /");
		return -EINVAL;
	}
	ret = seal_mkdir_p(keys_dir, 0700);
	if (ret)
		pr_err("mkdir %s: %s", keys_dir, strerror(-ret));
	return ret;
}

static int check_user_keys_dir(const char *keys_dir)
{
	char component[NAME_MAX + 1];
	struct stat st;
	const char *p, *end;
	int dirfd, nextfd, ret = 0;

	if (keys_dir[0] != '/')
		return -EINVAL;
	dirfd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dirfd < 0)
		return -errno;
	if (fstat(dirfd, &st) != 0) {
		ret = -errno;
		close(dirfd);
		return ret;
	}
	if (st.st_uid != 0 || (st.st_mode & 0022)) {
		close(dirfd);
		return -EPERM;
	}
	for (p = keys_dir + 1; *p; p = end ? end + 1 : p + strlen(p)) {
		size_t len;
		int final;

		end = strchr(p, '/');
		len = end ? (size_t)(end - p) : strlen(p);
		if (!len)
			continue;
		if (len > NAME_MAX) {
			ret = -ENAMETOOLONG;
			break;
		}
		memcpy(component, p, len);
		component[len] = '\0';
		nextfd = openat(dirfd, component,
				O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
		if (nextfd < 0) {
			ret = -errno;
			break;
		}
		if (fstat(nextfd, &st) != 0) {
			ret = -errno;
			close(nextfd);
			break;
		}
		final = !end || end[1] == '\0';
		if ((st.st_uid != 0 && st.st_uid != geteuid()) ||
		    (final && st.st_uid != geteuid()) ||
		    (st.st_mode & 0022)) {
			ret = -EPERM;
			close(nextfd);
			break;
		}
		close(dirfd);
		dirfd = nextfd;
		if (final)
			break;
	}
	close(dirfd);
	return ret;
}

static EVP_PKEY *gen_keypair(void)
{
	EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, GENKEY_ALG);

	if (!k) {
		openssl_complain("EVP_PKEY_Q_keygen");
		if (OPENSSL_version_major() < 3 ||
		    (OPENSSL_version_major() == 3 &&
		     OPENSSL_version_minor() < 5))
			pr_err("genkey: %s needs OpenSSL 3.5 or newer "
			       "(running %s); upgrade libcrypto",
			       GENKEY_ALG, OpenSSL_version(OPENSSL_VERSION));
	}
	return k;
}

/*
 * OpenSSL 4.0 returns the certificate's own names const, so build the
 * name apart and set it as both, which copies it.
 */
static int set_subject_and_issuer(X509 *c)
{
	X509_NAME *name = X509_NAME_new();
	int ret = -1;

	if (!name) {
		openssl_complain("X509_NAME_new");
		return -1;
	}
	if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
				       (const __u8 *)CERT_CN,
				       -1, -1, 0) != 1)
		openssl_complain("X509_NAME_add_entry_by_txt");
	else if (X509_set_subject_name(c, name) != 1)
		openssl_complain("X509_set_subject_name");
	else if (X509_set_issuer_name(c, name) != 1)
		openssl_complain("X509_set_issuer_name");
	else
		ret = 0;
	X509_NAME_free(name);
	return ret;
}

static int add_ext(X509 *c, int nid, const char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	int ret;

	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, c, c, NULL, NULL, 0);

	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex) {
		openssl_complain("X509V3_EXT_conf_nid");
		return -1;
	}
	ret = X509_add_ext(c, ex, -1);
	X509_EXTENSION_free(ex);
	if (ret != 1) {
		openssl_complain("X509_add_ext");
		return -1;
	}
	return 0;
}

static int build_serial(X509 *c)
{
	if (ASN1_INTEGER_set(X509_get_serialNumber(c), 1) != 1) {
		openssl_complain("ASN1_INTEGER_set");
		return -1;
	}
	return 0;
}

/*
 * Neither shirudo nor the kernel compares a certificate's validity with
 * the clock; a key is retired by revoking it. notAfter therefore holds
 * the value RFC 5280 4.1.2.5 gives a certificate with no well-defined
 * expiration, not a date that reads as the end of the key's trust.
 */
static int build_validity(X509 *c)
{
	if (!X509_gmtime_adj(X509_getm_notBefore(c), 0)) {
		openssl_complain("X509_gmtime_adj notBefore");
		return -1;
	}
	if (ASN1_TIME_set_string_X509(X509_getm_notAfter(c),
				      CERT_NO_EXPIRY) != 1) {
		openssl_complain("ASN1_TIME_set_string_X509 notAfter");
		return -1;
	}
	return 0;
}

/* ML-DSA hashes the message internally; OpenSSL requires a NULL digest. */
static int build_cert(X509 *c, EVP_PKEY *pkey)
{
	if (X509_set_version(c, 2) != 1) {	/* X.509 v3 */
		openssl_complain("X509_set_version");
		return -1;
	}
	if (build_serial(c) != 0)
		return -1;
	if (build_validity(c) != 0)
		return -1;
	if (X509_set_pubkey(c, pkey) != 1) {
		openssl_complain("X509_set_pubkey");
		return -1;
	}
	if (set_subject_and_issuer(c) != 0)
		return -1;

	if (add_ext(c, NID_basic_constraints, "critical,CA:FALSE") != 0)
		return -1;
	if (add_ext(c, NID_key_usage, "digitalSignature") != 0)
		return -1;
	if (add_ext(c, NID_subject_key_identifier, "hash") != 0)
		return -1;
	if (add_ext(c, NID_authority_key_identifier, "keyid:always") != 0)
		return -1;

	if (X509_sign(c, pkey, NULL) == 0) {
		openssl_complain("X509_sign");
		return -1;
	}
	return 0;
}

static int write_private_pem(EVP_PKEY *pkey, const char *path)
{
	int fd, ret = -1;
	BIO *b = NULL;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0) {
		pr_err("open %s: %s", path, strerror(errno));
		return -1;
	}
	if (fchmod(fd, 0600) != 0) {
		pr_err("fchmod %s: %s", path, strerror(errno));
		goto out;
	}
	/* Unbuffered, where a FILE would keep the key in memory freed unscrubbed. */
	b = BIO_new_fd(fd, BIO_NOCLOSE);
	if (!b) {
		openssl_complain("BIO_new_fd");
		goto out;
	}
	if (PEM_write_bio_PrivateKey(b, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
		openssl_complain("PEM_write_bio_PrivateKey");
		goto out;
	}
	if (fsync(fd) != 0) {
		pr_err("flush %s: %s", path, strerror(errno));
		goto out;
	}
	ret = 0;
out:
	BIO_free(b);
	close(fd);
	if (ret != 0)
		unlink(path);
	return ret;
}

static int write_cert_der(X509 *c, const char *path)
{
	int fd, ret = -1;
	BIO *bio = NULL;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0) {
		pr_err("open %s: %s", path, strerror(errno));
		return -1;
	}
	if (fchmod(fd, 0600) != 0) {
		pr_err("fchmod %s: %s", path, strerror(errno));
		goto out;
	}
	bio = BIO_new_fd(fd, BIO_NOCLOSE);
	if (!bio) {
		openssl_complain("BIO_new_fd");
		goto out;
	}
	if (i2d_X509_bio(bio, c) != 1) {
		openssl_complain("i2d_X509_bio");
		goto out;
	}
	if (fsync(fd) != 0) {
		pr_err("fsync %s: %s", path, strerror(errno));
		goto out;
	}
	ret = 0;
out:
	BIO_free(bio);
	close(fd);
	if (ret != 0)
		unlink(path);
	return ret;
}

/*
 * The two renames cannot be one, so the old key stays linked aside until
 * the new certificate is in place: a rename that fails between them puts
 * the old key back rather than leave the new key beside a certificate it
 * does not match.
 */
static int replace_pair(const char *pkey_new, const char *pkey_path,
			const char *cert_new, const char *cert_path,
			const char *pkey_old)
{
	bool had_old = true;
	int err;

	if (link(pkey_path, pkey_old) != 0) {
		if (errno != ENOENT) {
			err = errno;
			pr_err("genkey: cannot keep the old key aside as %s: %s",
			       pkey_old, strerror(err));
			return -err;
		}
		had_old = false;
	}
	if (rename(pkey_new, pkey_path) != 0) {
		err = errno;
		pr_err("genkey: cannot move %s to %s: %s", pkey_new, pkey_path,
		       strerror(err));
		if (had_old)
			unlink(pkey_old);
		return -err;
	}
	if (rename(cert_new, cert_path) != 0) {
		err = errno;
		pr_err("genkey: cannot move %s to %s: %s", cert_new, cert_path,
		       strerror(err));
		if (had_old ? rename(pkey_old, pkey_path) : unlink(pkey_path))
			pr_err("genkey: %s and %s are no longer a pair (%s); remove both and run genkey again",
			       pkey_path, cert_path, strerror(errno));
		return -err;
	}
	if (had_old)
		unlink(pkey_old);
	return 0;
}

enum genkey_opt {
	GENKEY_FORCE,
	GENKEY_KEYS_DIR,
};

static const struct opt_spec genkey_opts[] = {
	[GENKEY_FORCE] = { "--force", 'f', 0, NULL,
		"overwrite an existing key/cert (refused otherwise)" },
	[GENKEY_KEYS_DIR] = { "--keys-dir", 0, 0, "<dir>",
		"write signing_key.pem and cert.der under <dir> instead of the default" },
};

static const struct help_section genkey_help_sections[] = {
	HELP_OPTIONS("options:", genkey_opts),
};

static const struct help genkey_help = {
	.usage   = "shirudo genkey [--force] [--keys-dir <dir>]",
	.summary = "Generate a self-signed X.509 certificate and an ML-DSA-87 (FIPS 204) "
		   "private key\nfor signing .upatch loader bytes. "
		   "Operator-only; needs OpenSSL >= 3.5.",
	.sections   = genkey_help_sections,
	.n_sections = ARRAY_SIZE(genkey_help_sections),
	.footer  = "Default output paths:\n"
		   "  " SIGNING_KEY_PATH "\n"
		   "  " CERT_PATH "\n"
		   "If unset on the command line, the " KEYS_DIR_ENV
		   " environment variable\noverrides the default directory.",
};

int cmd_genkey(int argc, const char **argv)
{
	const char *keys_dir_arg = NULL;
	char pkey_path[PATH_MAX];
	char cert_path[PATH_MAX];
	EVP_PKEY *pkey = NULL;
	struct opt_parser p;
	const char *keys_dir;
	X509 *cert = NULL;
	int force = 0;
	int ret = 1;
	int opt;

	OPT_INIT(&p, "genkey", genkey_opts, &genkey_help, argc, argv, 1);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case GENKEY_FORCE:
			force = 1;
			break;
		case GENKEY_KEYS_DIR:
			keys_dir_arg = p.value;
			break;
		case OPT_DONE:
			return 0;
		case OPT_ARG:
			opt_usage(&p, "takes no argument, got '%s'", p.value);
			return EXIT_USAGE;
		default:
			return EXIT_USAGE;
		}
	}

	/*
	 * A target never holds a private key, and its task has the authority
	 * the seal denies root, which would write the pair wherever root asks.
	 */
	if (enforcement_active()) {
		pr_err("genkey: refusing on a target: the signing key belongs on the operator host");
		return 1;
	}

	keys_dir = keys_dir_resolve(keys_dir_arg);

	ret = key_paths(keys_dir, pkey_path, sizeof(pkey_path),
			cert_path, sizeof(cert_path));
	if (ret) {
		pr_err("genkey: invalid keys dir %s: %s",
		       keys_dir, strerror(-ret));
		return 1;
	}

	if (ensure_keys_dir(keys_dir) != 0)
		return 1;
	if (geteuid() != 0 && strcmp(keys_dir, KEYS_DIR) == 0) {
		ret = check_user_keys_dir(keys_dir);
		if (ret) {
			pr_err("genkey: default keys dir %s is not safe for user key "
			       "generation: %s", KEYS_DIR,
			       strerror(-ret));
			pr_err("it must be owned by the current user and not writable "
			       "by group or others");
			pr_err("rerun with sudo or pass --keys-dir <dir>");
			return 1;
		}
	}
	ret = 1;

	if (!force && (path_exists(pkey_path) ||
		       path_exists(cert_path))) {
		pr_err("genkey: %s or %s already exists; pass --force",
		       pkey_path, cert_path);
		return 1;
	}

	pkey = gen_keypair();
	if (!pkey)
		goto out;
	cert = X509_new();
	if (!cert) {
		openssl_complain("X509_new");
		goto out;
	}
	if (build_cert(cert, pkey) != 0)
		goto out;

	if (force) {
		char pkey_new[PATH_MAX], cert_new[PATH_MAX];
		char pkey_old[PATH_MAX];

		/* The old pair goes only once the new one is on disk. */
		if (strsprintf(pkey_new, sizeof(pkey_new), "%s.new",
			       pkey_path) < 0 ||
		    strsprintf(cert_new, sizeof(cert_new), "%s.new",
			       cert_path) < 0 ||
		    strsprintf(pkey_old, sizeof(pkey_old), "%s.old",
			       pkey_path) < 0) {
			pr_err("genkey: no room for a temporary beside %s",
			       pkey_path);
			goto out;
		}
		unlink(pkey_new);
		unlink(cert_new);
		unlink(pkey_old);
		if (write_private_pem(pkey, pkey_new) != 0)
			goto out;
		if (write_cert_der(cert, cert_new) != 0) {
			unlink(pkey_new);
			goto out;
		}
		if (replace_pair(pkey_new, pkey_path, cert_new, cert_path,
				 pkey_old) != 0) {
			unlink(pkey_new);
			unlink(cert_new);
			goto out;
		}
	} else {
		if (write_private_pem(pkey, pkey_path) != 0)
			goto out;
		if (write_cert_der(cert, cert_path) != 0) {
			unlink(pkey_path);
			goto out;
		}
	}

	pr_info("wrote %s (%s, mode 0600)", pkey_path, GENKEY_ALG);
	pr_info("wrote %s (X.509 self-signed, no expiration date)",
		cert_path);
	pr_audit("genkey: created shirudo %s signing material at %s",
		 GENKEY_ALG, keys_dir);
	ret = 0;
out:
	X509_free(cert);
	EVP_PKEY_free(pkey);
	return ret;
}
