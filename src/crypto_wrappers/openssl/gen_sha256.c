/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/crypto_wrapper.h>
#include <openssl/sha.h>

crypto_wrapper_err_t openssl_gen_sha256(crypto_wrapper_ctx_t *ctx, uint8_t *data, size_t size,
					uint8_t *hash)
{
	RTLS_DEBUG("ctx %p, data %p, size %zu hash %p\n", ctx, data, size, hash);
	SHA256(data, size, hash);

	return CRYPTO_WRAPPER_ERR_NONE;
}