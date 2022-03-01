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
	switch (hash_algo) {
	case SHA_ALGO_256:
		assert(digest_len == SHA256_DIGEST_LENGTH);

		SHA256_CTX context_256;

		if (SHA256_Init(&context_256) != 1)
			return false;
		if (SHA256_Update(&context_256, (void *)msg, msg_len) != 1)
			return false;
		if (SHA256_Final(digest, &context_256) != 1)
			return false;
		break;
	case SHA_ALGO_384:
		assert(digest_len == SHA384_DIGEST_LENGTH);

		SHA512_CTX context_512;

		if (SHA384_Init(&context_512) != 1)
			return false;
		if (SHA384_Update(&context_512, (void *)msg, msg_len) != 1)
			return false;
		if (SHA384_Final(digest, &context_512) != 1)
			return false;
		break;
	default:
		RTLS_ERR("unsupported sha type\n");
		return false;
	}

	return true;
}

static bool ecdsa_verify(sev_sig *sig, EVP_PKEY **pub_evp_key, uint8_t *digest, size_t length)
{
	bool is_valid = false;
	EC_KEY *pub_ec_key = NULL;
	BIGNUM *r = NULL;
	BIGNUM *s = NULL;
	ECDSA_SIG *ecdsa_sig = NULL;

	pub_ec_key = EVP_PKEY_get1_EC_KEY(*pub_evp_key);
	if (!pub_ec_key) {
		EC_KEY_free(pub_ec_key);
		return is_valid;
	}

	/* Store the x and y components as separate BIGNUM objects. The values in the
	 * SEV certificate are little-endian, must reverse bytes before storing in BIGNUM
	 */
	r = BN_lebin2bn(sig->ecdsa.r, sizeof(sig->ecdsa.r), NULL);
	s = BN_lebin2bn(sig->ecdsa.s, sizeof(sig->ecdsa.s), NULL);

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

	/* Validation will also be done by the FW */
	if (ECDSA_do_verify(digest, (uint32_t)length, ecdsa_sig, pub_ec_key) != 1) {
		RTLS_ERR("failed to verify ecdsa\n");
		goto err;
	}

	is_valid = true;

err:
	if (ecdsa_sig)
		ECDSA_SIG_free(ecdsa_sig);

	if (pub_ec_key)
		EC_KEY_free(pub_ec_key);

	return is_valid;
}

static bool rsa_verify(sev_sig *sig, EVP_PKEY **evp_pub_key, const uint8_t *hash, size_t hash_len,
		       SHA_TYPE hash_algo, bool pss)
{
	bool is_valid = false;
	RSA *rsa_pub_key = NULL;
	uint32_t sig_len = 0;

	/* Pull the RSA key from the EVP_PKEY */
	rsa_pub_key = EVP_PKEY_get1_RSA(*evp_pub_key);
	if (!rsa_pub_key)
		return is_valid;

	sig_len = RSA_size(rsa_pub_key);

	if (pss) {
		uint8_t decrypted[4096 / BITS_PER_BYTE] = { 0 };
		uint8_t signature[4096 / BITS_PER_BYTE] = { 0 };

		memset(decrypted, 0, sizeof(decrypted));
		memset(signature, 0, sizeof(signature));

		memcpy(signature, sig->rsa.s, 4096 / BITS_PER_BYTE);
		if (!reverse_bytes(signature, 4096 / BITS_PER_BYTE))
			goto err;

		/* Decrypt of the signature */
		if (RSA_public_decrypt(sig_len, signature, decrypted, rsa_pub_key,
				       RSA_NO_PADDING) == -1)
			goto err;

		/* sLen is -2 means salt length is recovered from the signature. */
		if (RSA_verify_PKCS1_PSS(rsa_pub_key, hash,
					 (hash_algo == SHA_ALGO_256) ? EVP_sha256() : EVP_sha384(),
					 decrypted, -2) != 1) {
			RTLS_ERR("failed to verify rsa with pss\n");
			goto err;
		}
	} else {
		/* Verify the data */
		if (RSA_verify((hash_algo == SHA_ALGO_256) ? NID_sha256 : NID_sha384, hash,
			       (uint32_t)hash_len, sig->rsa.s, sig_len, rsa_pub_key) != 1) {
			RTLS_ERR("failed to verify rsa without pss\n");
			goto err;
		}
	}

	is_valid = true;

err:
	if (rsa_pub_key)
		RSA_free(rsa_pub_key);

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
