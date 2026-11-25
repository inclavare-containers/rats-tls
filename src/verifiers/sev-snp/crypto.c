/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <assert.h>
#include <openssl/sha.h>
#include <openssl/ts.h>
#include <rats-tls/log.h>
#include "crypto.h"

#define BITS_PER_BYTE 8

/* The caller of digest_sha() must ensure the @digest_len is
 * correctly corresponding to @hash_algo
 */
bool digest_sha(const void *msg, size_t msg_len, uint8_t *digest, size_t digest_len,
		SHA_TYPE hash_algo)
{
	const EVP_MD *md = NULL;

	switch (hash_algo) {
	case SHA_ALGO_256:
		assert(digest_len == SHA256_DIGEST_LENGTH);
		md = EVP_sha256();
		break;
	case SHA_ALGO_384:
		assert(digest_len == SHA384_DIGEST_LENGTH);
		md = EVP_sha384();
		break;
	default:
		RTLS_ERR("unsupported sha type\n");
		return false;
	}

	return EVP_Digest(msg, msg_len, digest, NULL, md, NULL) == 1;
}

static bool ecdsa_verify(sev_sig *sig, EVP_PKEY **pub_evp_key, uint8_t *digest, size_t length)
{
	bool is_valid = false;
	BIGNUM *r = NULL;
	BIGNUM *s = NULL;
	ECDSA_SIG *ecdsa_sig = NULL;
	unsigned char *der_sig = NULL;
	EVP_PKEY_CTX *pctx = NULL;

	if (!pub_evp_key || !*pub_evp_key)
		return is_valid;

	/* Store the x and y components as separate BIGNUM objects. The values in the
	 * SEV certificate are little-endian, must reverse bytes before storing in BIGNUM
	 */
	r = BN_lebin2bn(sig->ecdsa.r, sizeof(sig->ecdsa.r), NULL);
	s = BN_lebin2bn(sig->ecdsa.s, sizeof(sig->ecdsa.s), NULL);
	if (!r || !s)
		goto err;

	/* Create a ecdsa_sig from the bignums and store in sig */
	ecdsa_sig = ECDSA_SIG_new();
	if (!ecdsa_sig) {
		RTLS_ERR("failed to allocate ECDSA_SIG structure\n");
		goto err;
	}

	if (ECDSA_SIG_set0(ecdsa_sig, r, s) != 1) {
		RTLS_ERR("failed to set the ecdsa_sig\n");
		goto err;
	}
	r = NULL;
	s = NULL;

	int der_len = i2d_ECDSA_SIG(ecdsa_sig, &der_sig);
	if (der_len <= 0) {
		RTLS_ERR("failed to encode ECDSA_SIG\n");
		goto err;
	}

	pctx = EVP_PKEY_CTX_new(*pub_evp_key, NULL);
	if (!pctx || EVP_PKEY_verify_init(pctx) <= 0) {
		RTLS_ERR("failed to init ecdsa verify\n");
		goto err;
	}

	/* Validation will also be done by the FW */
	if (EVP_PKEY_verify(pctx, der_sig, (size_t)der_len, digest, length) != 1) {
		RTLS_ERR("failed to verify ecdsa\n");
		goto err;
	}

	is_valid = true;

err:
	if (pctx)
		EVP_PKEY_CTX_free(pctx);
	if (der_sig)
		OPENSSL_free(der_sig);
	if (ecdsa_sig)
		ECDSA_SIG_free(ecdsa_sig);
	if (r)
		BN_free(r);
	if (s)
		BN_free(s);

	return is_valid;
}

static bool rsa_verify(sev_sig *sig, EVP_PKEY **evp_pub_key, const uint8_t *hash, size_t hash_len,
		       SHA_TYPE hash_algo, bool pss)
{
	bool is_valid = false;
	EVP_PKEY_CTX *pctx = NULL;
	const EVP_MD *md = (hash_algo == SHA_ALGO_256) ? EVP_sha256() : EVP_sha384();

	if (!evp_pub_key || !*evp_pub_key)
		return is_valid;

	int sig_len = EVP_PKEY_size(*evp_pub_key);
	if (sig_len <= 0 || (size_t)sig_len > sizeof(sig->rsa.s))
		return is_valid;

	pctx = EVP_PKEY_CTX_new(*evp_pub_key, NULL);
	if (!pctx || EVP_PKEY_verify_init(pctx) <= 0)
		goto err;

	if (EVP_PKEY_CTX_set_signature_md(pctx, md) <= 0)
		goto err;

	if (pss) {
		uint8_t signature[4096 / BITS_PER_BYTE] = { 0 };

		memcpy(signature, sig->rsa.s, 4096 / BITS_PER_BYTE);
		if (!reverse_bytes(signature, 4096 / BITS_PER_BYTE))
			goto err;

		if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
		    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -2) <= 0)
			goto err;

		if (EVP_PKEY_verify(pctx, signature, (size_t)sig_len, hash, hash_len) != 1) {
			RTLS_ERR("failed to verify rsa with pss\n");
			goto err;
		}
	} else {
		if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0)
			goto err;

		if (EVP_PKEY_verify(pctx, sig->rsa.s, (size_t)sig_len, hash, hash_len) != 1) {
			RTLS_ERR("failed to verify rsa without pss\n");
			goto err;
		}
	}

	is_valid = true;

err:
	if (pctx)
		EVP_PKEY_CTX_free(pctx);

	return is_valid;
}

bool verify_message(sev_sig *sig, EVP_PKEY **evp_key_pair, const uint8_t *msg, size_t length,
		    const SEV_SIG_ALGO algo)
{
	hmac_sha_256 sha256_digest;
	hmac_sha_384 sha384_digest;
	SHA_TYPE hash_algo;
	uint8_t *hash = NULL;
	size_t hash_len;
	const bool pss = true;

	switch (algo) {
	case SEV_SIG_ALGO_RSA_SHA256:
	case SEV_SIG_ALGO_ECDSA_SHA256:
	case SEV_SIG_ALGO_ECDH_SHA256:
		hash_algo = SHA_ALGO_256;
		hash = sha256_digest;
		hash_len = sizeof(hmac_sha_256);
		break;
	case SEV_SIG_ALGO_RSA_SHA384:
	case SEV_SIG_ALGO_ECDSA_SHA384:
	case SEV_SIG_ALGO_ECDH_SHA384:
		hash_algo = SHA_ALGO_384;
		hash = sha384_digest;
		hash_len = sizeof(hmac_sha_384);
		break;
	default:
		return false;
	}

	memset(hash, 0, hash_len);

	/* Calculate the hash digest */
	if (!digest_sha(msg, length, hash, hash_len, hash_algo))
		return false;

	switch (algo) {
	case SEV_SIG_ALGO_RSA_SHA256:
	case SEV_SIG_ALGO_RSA_SHA384:
		if (!rsa_verify(sig, evp_key_pair, hash, hash_len, hash_algo, pss))
			return false;
		break;
	case SEV_SIG_ALGO_ECDSA_SHA256:
	case SEV_SIG_ALGO_ECDSA_SHA384:
		if (!ecdsa_verify(sig, evp_key_pair, hash, hash_len))
			return false;
		break;
	case SEV_SIG_ALGO_ECDH_SHA256:
	case SEV_SIG_ALGO_ECDH_SHA384:
		RTLS_ERR("unsupported ECDH signing\n");
		return false;
	default:
		RTLS_ERR("invalid signing algo\n");
		return false;
	}

	return true;
}
