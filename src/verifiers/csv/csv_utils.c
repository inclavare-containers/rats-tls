/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/evp.h>
#include <openssl/hmac.h>

int sm3_hmac(const char *key, size_t key_len, const unsigned char *data, size_t data_len,
	     unsigned char *hmac, size_t expected_hmac_len)
{
	HMAC_CTX *hmac_ctx = HMAC_CTX_new();
	const EVP_MD *evp_md = EVP_sm3();
	int sm3_hmac_out_size = 0;
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
}
