/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/crypto_wrapper.h>
#include "openssl.h"

crypto_wrapper_err_t openssl_use_privkey(crypto_wrapper_ctx_t *ctx, rats_tls_cert_algo_t *algo,
					 const uint8_t *privkey_buf, size_t privkey_len,
					 const uint8_t *pubkey_buf, size_t pubkey_len)
{
	openssl_ctx *octx = NULL;
	const unsigned char *p = privkey_buf;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY *pub_pkey = NULL;
	rats_tls_cert_algo_t detected_algo;

	RTLS_DEBUG("ctx %p, algo %p, privkey_buf %p, privkey_len %zu, pubkey_buf %p, pubkey_len %zu\n",
		   ctx, algo, privkey_buf, privkey_len, pubkey_buf, pubkey_len);

	if (!ctx || !algo || !privkey_buf || !privkey_len)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	if ((pubkey_buf && !pubkey_len) || (!pubkey_buf && pubkey_len))
		return -CRYPTO_WRAPPER_ERR_INVALID;

	octx = ctx->crypto_private;
	if (!octx)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	pkey = d2i_AutoPrivateKey(NULL, &p, (long)privkey_len);
	if (!pkey || p != privkey_buf + privkey_len) {
		RTLS_ERR("failed to decode DER private key\n");
		if (pkey)
			EVP_PKEY_free(pkey);
		return -CRYPTO_WRAPPER_ERR_PRIV_KEY_LEN;
	}

	switch (EVP_PKEY_base_id(pkey)) {
	case EVP_PKEY_EC: {
		EC_KEY *eckey = EVP_PKEY_get0_EC_KEY(pkey);
		if (!eckey || !EC_KEY_check_key(eckey)) {
			EVP_PKEY_free(pkey);
			return -CRYPTO_WRAPPER_ERR_ECC_KEY_LEN;
		}
		detected_algo = RATS_TLS_CERT_ALGO_ECC_256_SHA256;
		break;
	}
	case EVP_PKEY_RSA: {
		RSA *rsa = EVP_PKEY_get0_RSA(pkey);
		if (!rsa || RSA_check_key(rsa) != 1) {
			EVP_PKEY_free(pkey);
			return -CRYPTO_WRAPPER_ERR_RSA_KEY_LEN;
		}
		detected_algo = RATS_TLS_CERT_ALGO_RSA_3072_SHA256;
		break;
	}
	default:
		RTLS_ERR("unsupported DER private key type %d\n", EVP_PKEY_base_id(pkey));
		EVP_PKEY_free(pkey);
		return -CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;
	}

	if (pubkey_buf) {
		const unsigned char *pub_p = pubkey_buf;
		pub_pkey = d2i_PUBKEY(NULL, &pub_p, (long)pubkey_len);
		if (!pub_pkey || pub_p != pubkey_buf + pubkey_len) {
			RTLS_ERR("failed to decode DER public key\n");
			if (pub_pkey)
				EVP_PKEY_free(pub_pkey);
			EVP_PKEY_free(pkey);
			return -CRYPTO_WRAPPER_ERR_PUB_KEY_DECODE;
		}
		if (EVP_PKEY_cmp(pkey, pub_pkey) != 1) {
			RTLS_ERR("DER public key does not match private key\n");
			EVP_PKEY_free(pub_pkey);
			EVP_PKEY_free(pkey);
			return -CRYPTO_WRAPPER_ERR_INVALID;
		}
		EVP_PKEY_free(pub_pkey);
	}

	if (octx->pkey)
		EVP_PKEY_free(octx->pkey);
	octx->pkey = pkey;
	*algo = detected_algo;

	RTLS_DEBUG("configured custom DER private key, detected cert_algo=%d\n", detected_algo);

	return CRYPTO_WRAPPER_ERR_NONE;
}
