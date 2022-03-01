/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x10100000L
// clang-format off
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
// clang-format on

int X509_STORE_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
				CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
	return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE, argl, argp, new_func, dup_func,
				       free_func);
}

const STACK_OF(X509_EXTENSION) * X509_get0_extensions(const X509 *x)
{
	return x->cert_info->extensions;
}

int X509_STORE_set_ex_data(X509_STORE *ctx, int idx, void *data)
{
	return CRYPTO_set_ex_data(&ctx->ex_data, idx, data);
}

void *X509_STORE_get_ex_data(const X509_STORE *ctx, int idx)
{
	return CRYPTO_get_ex_data(&ctx->ex_data, idx);
}

X509_STORE *X509_STORE_CTX_get0_store(X509_STORE_CTX *ctx)
{
	return ctx->ctx;
}

/* Flags for X509_get_signature_info() */
/* Signature info is valid */
#define X509_SIG_INFO_VALID 0x1
/* Signature is suitable for TLS use */
#define X509_SIG_INFO_TLS 0x2

static int X509_sig_info_get(const X509 *x, int *mdnid, int *pknid, int *secbits, uint32_t *flags)
{
	int siginf_mdnid = NID_undef;
	int siginf_pknid = NID_undef;
	int siginf_secbits = -1;
	uint32_t siginf_flags = 0;

	if (!OBJ_find_sigid_algs(OBJ_obj2nid(x->sig_alg->algorithm), &siginf_mdnid,
				 &siginf_pknid) || (siginf_pknid == NID_undef))
		goto ret;

	if (siginf_mdnid == NID_undef)
		goto ret;

	siginf_flags |= X509_SIG_INFO_VALID;
	const EVP_MD *md = EVP_get_digestbynid(siginf_mdnid);
	if (md == NULL)
		goto ret;

	switch (siginf_mdnid) {
	case NID_sha1:
	case NID_sha256:
	case NID_sha384:
	case NID_sha512:
		siginf_flags |= X509_SIG_INFO_TLS;
	}

ret:
	if (mdnid != NULL)
		*mdnid = siginf_mdnid;
	if (pknid != NULL)
		*pknid = siginf_pknid;
	if (secbits != NULL) {
		/* Security bits: half number of bits in digest */
		*secbits = EVP_MD_size(md) * 4;
	}
	if (flags != NULL)
		*flags = siginf_flags;

	return (siginf_flags & X509_SIG_INFO_VALID) != 0;
}

int X509_get_signature_info(X509 *x, int *mdnid, int *pknid, int *secbits, uint32_t *flags)
{
	X509_check_purpose(x, -1, -1);
	return X509_sig_info_get(x, mdnid, pknid, secbits, flags);
}

#endif
