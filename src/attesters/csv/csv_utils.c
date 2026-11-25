/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>
#include <rats-tls/log.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/params.h>
#else
#include <openssl/hmac.h>
#endif

void gen_random_bytes(void *buf, size_t len)
{
	uint32_t i;
	uint8_t *buf_byte = (uint8_t *)buf;

	for (i = 0; i < len; i++)
		buf_byte[i] = rand() & 0xFF;
}

int sm3_hash(const unsigned char *data, size_t len, unsigned char *hash, size_t expected_hash_len)
{
	EVP_MD_CTX *evp_md_ctx = EVP_MD_CTX_new();
	const EVP_MD *evp_md = EVP_sm3();
	unsigned int sm3_out_size = 0;
	int ret = -1;

	if (evp_md_ctx == NULL)
		return ret;

	if (!EVP_DigestInit_ex(evp_md_ctx, evp_md, NULL))
		goto err_free_md_ctx;

	if (!EVP_DigestUpdate(evp_md_ctx, data, len))
		goto err_free_md_ctx;

	if (!EVP_DigestFinal_ex(evp_md_ctx, hash, &sm3_out_size))
		goto err_free_md_ctx;

	if (sm3_out_size != expected_hash_len)
		goto err_free_md_ctx;

	ret = 0;

err_free_md_ctx:
	EVP_MD_CTX_free(evp_md_ctx);

	return ret;
}

int sm3_hmac(const char *key, size_t key_len, const unsigned char *data, size_t data_len,
	     unsigned char *hmac, size_t expected_hmac_len)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	EVP_MAC_CTX *mctx = NULL;
	size_t sm3_hmac_out_size = 0;
	int ret = -1;
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SM3", 0),
		OSSL_PARAM_construct_end(),
	};

	if (mac == NULL)
		return ret;

	mctx = EVP_MAC_CTX_new(mac);
	if (mctx == NULL)
		goto err_free_mac;

	if (!EVP_MAC_init(mctx, (const unsigned char *)key, key_len, params))
		goto err_free_mctx;

	if (!EVP_MAC_update(mctx, data, data_len))
		goto err_free_mctx;

	if (!EVP_MAC_final(mctx, hmac, &sm3_hmac_out_size, expected_hmac_len))
		goto err_free_mctx;

	if (sm3_hmac_out_size != expected_hmac_len)
		goto err_free_mctx;

	ret = 0;

err_free_mctx:
	EVP_MAC_CTX_free(mctx);
err_free_mac:
	EVP_MAC_free(mac);

	return ret;
#else
	HMAC_CTX *hmac_ctx = HMAC_CTX_new();
	const EVP_MD *evp_md = EVP_sm3();
	unsigned int sm3_hmac_out_size = 0;
	int ret = -1;

	if (hmac_ctx == NULL)
		return ret;

	if (!HMAC_Init_ex(hmac_ctx, key, key_len, evp_md, NULL))
		goto err_free_hmac_ctx;

	if (!HMAC_Update(hmac_ctx, data, data_len))
		goto err_free_hmac_ctx;

	if (!HMAC_Final(hmac_ctx, hmac, &sm3_hmac_out_size))
		goto err_free_hmac_ctx;

	if (sm3_hmac_out_size != expected_hmac_len)
		goto err_free_hmac_ctx;

	ret = 0;

err_free_hmac_ctx:
	HMAC_CTX_free(hmac_ctx);

	return ret;
#endif
}
